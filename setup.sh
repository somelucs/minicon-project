#!/bin/bash

# Aborta o script se qualquer comando falhar
set -e

# --- 1. Verificando privilégios e instalando dependências ---
if [ "$EUID" -ne 0 ]; then
  exit 1
fi

apt-get update

apt-get install -y build-essential clang libelf-dev libbpf-dev linux-headers-$(uname -r) debootstrap

# --- 2. Criando o diretório e os arquivos do projeto ---
PROJECT_DIR="minicon_project"
mkdir -p ${PROJECT_DIR}
cd ${PROJECT_DIR}

cat << 'EOF' > monitor.bpf.c
// monitor.bpf.c
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

struct event {
    char comm[16];
    char filename[256];
    __u32 pid;
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} rb SEC(".maps");

SEC("tp/syscalls/sys_enter_execve")
int handle_exec(struct trace_event_raw_sys_enter *ctx) {
    struct event *e;
    const char *filename_ptr;
    
    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e) {
        return 0;
    }

    e->pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    filename_ptr = (const char *) BPF_CORE_READ(ctx, args[0]);
    bpf_probe_read_user_str(&e->filename, sizeof(e->filename), filename_ptr);

    bpf_ringbuf_submit(e, 0);

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
EOF

cat << 'EOF' > mycontainer.c
// mycontainer.c
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <sched.h>
#include <sys/wait.h>
#include <unistd.h>
#include <sys/mount.h>
#include <string.h>
#include <errno.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include "monitor.skel.h" 

static int child_func(void *arg) {
    char **args = (char **)arg;
    char *rootfs_path = args[0];
    char **child_args = &args[1];


    // Seta um novo hostname para o container
    sethostname("my-container", 12);
    
    // Monta o /proc para que comandos como `ps` funcionem
    if (mount("proc", "/proc", "proc", 0, NULL) != 0) {
        perror("mount proc");
    }

    if (chroot(rootfs_path) != 0) {
        perror("chroot");
        return 1;
    }
    chdir("/");

    execvp(child_args[0], child_args);
    
    perror("execvp");
    return 1;
}

int handle_event(void *ctx, void *data, size_t data_sz) {
    const struct event *e = data;
    return 0;
}

int main(int argc, char *argv[]) {
    if (argc < 3) {
        fprintf(stderr, "Uso: %s <caminho-para-rootfs> <comando> [args...]\n", argv[0]);
        return 1;
    }
    
    struct monitor_bpf *skel;
    struct ring_buffer *rb = NULL;
    int err;

    skel = monitor_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "Falha ao abrir e carregar o esqueleto BPF\n");
        return 1;
    }

    err = monitor_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Falha ao anexar o esqueleto BPF: %s\n", strerror(-err));
        goto cleanup;
    }

    rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
    if (!rb) {
        err = -1;
        fprintf(stderr, "Falha ao criar o ring buffer\n");
        goto cleanup;
    }


    char *stack = malloc(1024 * 1024);
    if (!stack) {
        perror("malloc");
        return 1;
    }
    char *stack_top = stack + (1024 * 1024);
    void *child_arg_ptr = &argv[1];
    int clone_flags = CLONE_NEWPID | CLONE_NEWNS | CLONE_NEWUTS | SIGCHLD;

    pid_t child_pid = clone(child_func, stack_top, clone_flags, child_arg_ptr);
    if (child_pid == -1) {
        perror("clone");
        free(stack);
        goto cleanup;
    }


    while (true) {
        err = ring_buffer__poll(rb, 100);
        int status;
        if (waitpid(child_pid, &status, WNOHANG) == child_pid) {
            break;
        }
        if (err < 0 && err != -EINTR) {
            fprintf(stderr, "Erro ao processar ring buffer: %d\n", err);
            break;
        }
    }

cleanup:
    ring_buffer__free(rb);
    monitor_bpf__destroy(skel);
    free(stack);
    return err < 0 ? -err : 0;
}
EOF

# --- 3. Criando o Root Filesystem com debootstrap ---
ROOTFS_DIR="rootfs"
if [ -d "$ROOTFS_DIR" ]; then
    echo "Diretório rootfs './${ROOTFS_DIR}' já existe. Pulando a criação."
else
    echo "Criando o rootfs em './${ROOTFS_DIR}' com debootstrap (isso pode demorar alguns minutos)..."
    debootstrap --variant=minbase jammy ${ROOTFS_DIR} http://archive.ubuntu.com/ubuntu/
fi


# --- 4. Compilando o projeto ---
echo "Compilando o programa BPF (clang)..."
clang -g -O2 -target bpf -c monitor.bpf.c -o monitor.o

echo "Gerando o esqueleto BPF (bpftool)..."
bpftool gen skeleton monitor.o > monitor.skel.h

echo "Compilando o runner do container (gcc)..."
gcc -g -o mycontainer mycontainer.c monitor.o -lbpf -lelf

# --- 5. Instruções Finais ---
GREEN='\033[0;32m'
NC='\033[0m'

echo -e "\n${GREEN}====================================================="
echo -e "Setup concluído com sucesso!"
echo -e "Todos os arquivos estão no diretório '${PROJECT_DIR}'."
echo -e "\nPara executar seu mini container, use o comando:"
echo -e "  sudo ./mycontainer ./${ROOTFS_DIR} /bin/bash"
echo -e "\nDentro do container, teste os comandos:"
echo -e "  # hostname (deve retornar 'my-container')"
echo -e "  # ps aux (deve mostrar o bash como PID 1)"
echo -e "  # ls /"
echo -e "\nSaia com 'exit' para ver os logs do BPF."
echo -e "=====================================================${NC}"
