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
