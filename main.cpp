/* This code is licensed under the GPLv3. You can find its text here:
   https://www.gnu.org/licenses/gpl-3.0.en.html */

// This is a C++ rewrite of the C code here:
// https://blog.lizzie.io/linux-containers-in-500-loc.html

#include <errno.h>
#include <fcntl.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <time.h>
#include <unistd.h>

#include <grp.h>
#include <pwd.h>
#include <sched.h>
#include <seccomp.h>
#include <sysexits.h>

#include <sys/capability.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <linux/capability.h>
#include <linux/limits.h>

#include <iostream>
#include <string>
#include <vector>

namespace {

// Plain old data types, no constructors/destructors so that we can send it simply to the child process
struct child_config {
    int argc;
    uid_t uid;
    int fd;
    char hostname[256];
    char** argv;
    char mount_dir[1024];
};

int capabilities()
{
    fprintf(stderr, "=> dropping capabilities...");
    const int drop_caps[] = {
        CAP_AUDIT_CONTROL,
        CAP_AUDIT_READ,
        CAP_AUDIT_WRITE,
        CAP_BLOCK_SUSPEND,
        CAP_DAC_READ_SEARCH,
        CAP_FSETID,
        CAP_IPC_LOCK,
        CAP_MAC_ADMIN,
        CAP_MAC_OVERRIDE,
        CAP_MKNOD,
        CAP_SETFCAP,
        CAP_SYSLOG,
        CAP_SYS_ADMIN,
        CAP_SYS_BOOT,
        CAP_SYS_MODULE,
        CAP_SYS_NICE,
        CAP_SYS_RAWIO,
        CAP_SYS_RESOURCE,
        CAP_SYS_TIME,
        CAP_WAKE_ALARM
    };
    const size_t num_caps = sizeof(drop_caps) / sizeof(*drop_caps);
    fprintf(stderr, "bounding...");
    for (size_t i = 0; i < num_caps; i++) {
        if (prctl(PR_CAPBSET_DROP, drop_caps[i], 0, 0, 0)) {
            fprintf(stderr, "prctl failed: %m\n");
            return 1;
        }
    }
    fprintf(stderr, "inheritable...");
    cap_t caps = nullptr;
    if (!(caps = cap_get_proc()) ||
            cap_set_flag(caps, CAP_INHERITABLE, num_caps, drop_caps, CAP_CLEAR) ||
            cap_set_proc(caps)) {
        fprintf(stderr, "failed: %m\n");
        if (caps) cap_free(caps);
        return 1;
    }
    cap_free(caps);
    fprintf(stderr, "done.\n");
    return 0;
}

int pivot_root(const char* new_root, const char* put_old)
{
    return syscall(SYS_pivot_root, new_root, put_old);
}

int mounts(const child_config& config)
{
    fprintf(stderr, "=> remounting everything with MS_PRIVATE...");
    if (mount(nullptr, "/", nullptr, MS_REC | MS_PRIVATE, nullptr)) {
        fprintf(stderr, "failed! %m\n");
        return -1;
    }
    fprintf(stderr, "remounted.\n");

    fprintf(stderr, "=> making a temp directory and a bind mount there...");
    char mount_dir[] = "/tmp/tmp.XXXXXX";
    if (!mkdtemp(mount_dir)) {
        fprintf(stderr, "failed making a directory!\n");
        return -1;
    }

    if (mount(config.mount_dir, mount_dir, nullptr, MS_BIND | MS_PRIVATE, nullptr)) {
        fprintf(stderr, "bind mount %s to %s failed!\n", config.mount_dir, mount_dir);
        return -1;
    }

    char inner_mount_dir[] = "/tmp/tmp.XXXXXX/oldroot.XXXXXX";
    memcpy(inner_mount_dir, mount_dir, sizeof(mount_dir) - 1);
    if (!mkdtemp(inner_mount_dir)) {
        fprintf(stderr, "failed making the inner directory!\n");
        return -1;
    }
    fprintf(stderr, "done.\n");

    fprintf(stderr, "=> pivoting root...");
    if (pivot_root(mount_dir, inner_mount_dir)) {
        fprintf(stderr, "failed!\n");
        return -1;
    }
    fprintf(stderr, "done.\n");

    const char* old_root_dir = basename(inner_mount_dir);
    const std::string old_root = "/" + std::string(old_root_dir);

    fprintf(stderr, "=> unmounting %s...", old_root.c_str());
    if (chdir("/")) {
        fprintf(stderr, "chdir failed! %m\n");
        return -1;
    }
    if (umount2(old_root.c_str(), MNT_DETACH)) {
        fprintf(stderr, "umount failed! %m\n");
        return -1;
    }
    if (rmdir(old_root.c_str())) {
        fprintf(stderr, "rmdir failed! %m\n");
        return -1;
    }
    fprintf(stderr, "done.\n");
    return 0;
}


#define SCMP_FAIL SCMP_ACT_ERRNO(EPERM)

int syscalls()
{
    fprintf(stderr, "=> filtering syscalls...");
    scmp_filter_ctx ctx = nullptr;
    if (!(ctx = seccomp_init(SCMP_ACT_ALLOW)) ||
            seccomp_rule_add(ctx, SCMP_FAIL, SCMP_SYS(chmod), 1, SCMP_A1(SCMP_CMP_MASKED_EQ, S_ISUID, S_ISUID)) ||
            seccomp_rule_add(ctx, SCMP_FAIL, SCMP_SYS(chmod), 1, SCMP_A1(SCMP_CMP_MASKED_EQ, S_ISGID, S_ISGID)) ||
            seccomp_rule_add(ctx, SCMP_FAIL, SCMP_SYS(fchmod), 1, SCMP_A1(SCMP_CMP_MASKED_EQ, S_ISUID, S_ISUID)) ||
            seccomp_rule_add(ctx, SCMP_FAIL, SCMP_SYS(fchmod), 1, SCMP_A1(SCMP_CMP_MASKED_EQ, S_ISGID, S_ISGID)) ||
            seccomp_rule_add(ctx, SCMP_FAIL, SCMP_SYS(fchmodat), 1, SCMP_A2(SCMP_CMP_MASKED_EQ, S_ISUID, S_ISUID)) ||
            seccomp_rule_add(ctx, SCMP_FAIL, SCMP_SYS(fchmodat), 1, SCMP_A2(SCMP_CMP_MASKED_EQ, S_ISGID, S_ISGID)) ||
            seccomp_rule_add(ctx, SCMP_FAIL, SCMP_SYS(unshare), 1, SCMP_A0(SCMP_CMP_MASKED_EQ, CLONE_NEWUSER, CLONE_NEWUSER)) ||
            seccomp_rule_add(ctx, SCMP_FAIL, SCMP_SYS(clone), 1, SCMP_A0(SCMP_CMP_MASKED_EQ, CLONE_NEWUSER, CLONE_NEWUSER)) ||
            seccomp_rule_add(ctx, SCMP_FAIL, SCMP_SYS(ioctl), 1, SCMP_A1(SCMP_CMP_MASKED_EQ, TIOCSTI, TIOCSTI)) ||
            seccomp_rule_add(ctx, SCMP_FAIL, SCMP_SYS(keyctl), 0) ||
            seccomp_rule_add(ctx, SCMP_FAIL, SCMP_SYS(add_key), 0) ||
            seccomp_rule_add(ctx, SCMP_FAIL, SCMP_SYS(request_key), 0) ||
            seccomp_rule_add(ctx, SCMP_FAIL, SCMP_SYS(ptrace), 0) ||
            seccomp_rule_add(ctx, SCMP_FAIL, SCMP_SYS(mbind), 0) ||
            seccomp_rule_add(ctx, SCMP_FAIL, SCMP_SYS(migrate_pages), 0) ||
            seccomp_rule_add(ctx, SCMP_FAIL, SCMP_SYS(move_pages), 0) ||
            seccomp_rule_add(ctx, SCMP_FAIL, SCMP_SYS(set_mempolicy), 0) ||
            seccomp_rule_add(ctx, SCMP_FAIL, SCMP_SYS(userfaultfd), 0) ||
            seccomp_rule_add(ctx, SCMP_FAIL, SCMP_SYS(perf_event_open), 0) ||
            seccomp_attr_set(ctx, SCMP_FLTATR_CTL_NNP, 0) ||
            seccomp_load(ctx)) {
        if (ctx) seccomp_release(ctx);
        fprintf(stderr, "failed: %m\n");
        return 1;
    }
    seccomp_release(ctx);
    fprintf(stderr, "done.\n");
    return 0;
}

const char* MEMORY = "1073741824";
const char* SHARES = "256";
const char* PIDS = "64";
const char* WEIGHT = "10";
const size_t FD_COUNT = 64;

struct cgrp_setting {
    std::string name;
    std::string value;
};

struct cgrp_control {
    std::string control;
    std::vector<cgrp_setting> settings;
};

std::vector<cgrp_control> cgrps = {
        {
        "memory",
        {
            {
                "memory.limit_in_bytes",
                MEMORY
            },
            {
                "memory.kmem.limit_in_bytes",
                MEMORY
            },
            {
                "tasks",
                "0"
            },
        }
    },
    {
        "cpu",
        {
            {
                "cpu.shares",
                SHARES
            },
            {
                "tasks",
                "0"
            },
        }
    },
    {
        "pids",
        {
            {
                "pids.max",
                PIDS
            },
            {
                "tasks",
                "0"
            },
        }
    },
};

int resources(const child_config& config)
{
    fprintf(stderr, "=> setting cgroups...\n");
    for (auto&& cgrp : cgrps) {
        std::cerr<<cgrp.control<<"..."<<std::endl;
        const std::string dir = "/sys/fs/cgroup/" + cgrp.control + "/" + config.hostname;
        if (mkdir(dir.c_str(), S_IRUSR | S_IWUSR | S_IXUSR)) {
            fprintf(stderr, "mkdir %s failed: %m\n", dir.c_str());
            return -1;
        }
        for (auto&& setting : cgrp.settings) {
            int fd = 0;
            const std::string path = dir + "/" + setting.name;
            if ((fd = open(path.c_str(), O_WRONLY)) == -1) {
                fprintf(stderr, "opening %s failed: %m\n", path.c_str());
                return -1;
            }
            if (write(fd, setting.value.c_str(), setting.value.length()) == -1) {
                fprintf(stderr, "writing to %s failed: %m\n", path.c_str());
                close(fd);
                return -1;
            }
            close(fd);
        }

        // This file doesn't exist yet on ubuntu and we didn't have permissions to create it:
        // /sys/fs/cgroup/blkio/1f8fabc-knight-of-pentacles/blkio.weight
        // So we just attempt to write it and don't worry if we fail
        {
            const char* name = "blkio.weight";
            const char* value = WEIGHT;

            const std::string path = dir + "/" + name;
            int fd = 0;
            if ((fd = open(path.c_str(), O_WRONLY)) == -1) {
                fprintf(stderr, "opening %s failed: %m\n", path.c_str());
            } else {
                if (write(fd, value, strlen(value)) == -1) {
                    fprintf(stderr, "writing to %s failed: %m\n", path.c_str());
                }

                close(fd);
            }
        }
    }
    fprintf(stderr, "done.\n");
    fprintf(stderr, "=> setting rlimit...");
    const rlimit limit = {
        FD_COUNT,
        FD_COUNT,
    };
    if (setrlimit(RLIMIT_NOFILE, &limit)) {
        fprintf(stderr, "failed: %m\n");
        return 1;
    }
    fprintf(stderr, "done.\n");
    return 0;
}

int free_resources(const child_config& config)
{
    fprintf(stderr, "=> cleaning cgroups...");
    for (auto&& cgrp : cgrps) {
        const std::string dir = "/sys/fs/cgroup/" + cgrp.control + "/" + config.hostname;
        const std::string task = "/sys/fs/cgroup/" + cgrp.control + "/tasks";
        int task_fd = 0;
        if ((task_fd = open(task.c_str(), O_WRONLY)) == -1) {
            fprintf(stderr, "opening %s failed: %m\n", task.c_str());
            return -1;
        }
        if (write(task_fd, "0", 2) == -1) {
            fprintf(stderr, "writing to %s failed: %m\n", task.c_str());
            close(task_fd);
            return -1;
        }
        close(task_fd);
        if (rmdir(dir.c_str())) {
            fprintf(stderr, "rmdir %s failed: %m", dir.c_str());
            return -1;
        }
    }
    fprintf(stderr, "done.\n");
    return 0;
}

const int USERNS_OFFSET = 10000;
const int USERNS_COUNT = 2000;

bool handle_child_uid_map(pid_t child_pid, int fd)
{
    int has_userns = -1;
    if (read(fd, &has_userns, sizeof(has_userns)) != sizeof(has_userns)) {
        fprintf(stderr, "couldn't read from child!\n");
        return false;
    }
    if (has_userns) {
        const std::vector<std::string > files = {
            "uid_map",
            "gid_map"
        };
        for (auto&& file : files) {
            const std::string path = "/proc/" + std::to_string(child_pid) + "/" + file;
            fprintf(stderr, "writing %s...", path.c_str());
            int uid_map = 0;
            if ((uid_map = open(path.c_str(), O_WRONLY)) == -1) {
                fprintf(stderr, "open failed: %m\n");
                return false;
            }
            if (dprintf(uid_map, "0 %d %d\n", USERNS_OFFSET, USERNS_COUNT) == -1) {
                fprintf(stderr, "dprintf failed: %m\n");
                close(uid_map);
                return false;
            }
            close(uid_map);
        }
    }

    const int value = 0;
    if (write(fd, &value, sizeof(value)) != sizeof(value)) {
        fprintf(stderr, "couldn't write: %m\n");
        return false;
    }

    return true;
}

int userns(const child_config& config)
{
    fprintf(stderr, "=> trying a user namespace...");
    const int has_userns = !unshare(CLONE_NEWUSER);
    if (write(config.fd, &has_userns, sizeof(has_userns)) != sizeof(has_userns)) {
        fprintf(stderr, "couldn't write: %m\n");
        return -1;
    }
    int result = 0;
    if (read(config.fd, &result, sizeof(result)) != sizeof(result)) {
        fprintf(stderr, "couldn't read: %m\n");
        return -1;
    }
    if (result) return -1;

    if (has_userns) {
        fprintf(stderr, "done.\n");
    } else {
        fprintf(stderr, "unsupported? continuing.\n");
    }
    fprintf(stderr, "=> switching to uid %d / gid %d...", config.uid, config.uid);
    const gid_t gid = (gid_t)config.uid;
    if (setgroups(1, &gid) ||
        setresgid(config.uid, config.uid, config.uid) ||
        setresuid(config.uid, config.uid, config.uid)) {
        fprintf(stderr, "%m\n");
        return -1;
    }
    fprintf(stderr, "done.\n");
    return 0;
}

int child(void* arg)
{
    const child_config* config = (const child_config*)arg;
    if (sethostname(config->hostname, strlen(config->hostname)) ||
            mounts(*config) ||
            userns(*config) ||
            capabilities() ||
            syscalls()) {
        close(config->fd);
        return -1;
    }
    if (close(config->fd)) {
        fprintf(stderr, "close failed: %m\n");
        return -1;
    }
    if (execve(config->argv[0], config->argv, nullptr)) {
        fprintf(stderr, "execve failed! %m.\n");
        return -1;
    }
    return 0;
}

void print_usage(const char* argv0)
{
    fprintf(stderr, "Usage:\n");
    fprintf(stderr, " BUSYBOX_VERSION=1.33.0\n");
    fprintf(stderr, " sudo %s -h hostname -m $(realpath ./busybox-${BUSYBOX_VERSION}/) -u 0 -c /bin/sh\n", argv0);
}

bool parse_command_line_arguments(int argc, char** argv, child_config& config)
{
    int option = 0;
    int last_optind = 0;
    while ((option = getopt(argc, argv, "c:h:m:u:"))) {
        switch (option) {
            case 'c':
                // Pass the remaining arguments to the child
                // NOTE: This must be the last argument
                config.argc = argc - last_optind - 1;
                config.argv = &argv[argc - config.argc];
                return true;
            case 'h':
                strcpy(config.hostname, optarg);
                break;
            case 'm':
                strcpy(config.mount_dir, optarg);
                break;
            case 'u':
                if (sscanf(optarg, "%d", &config.uid) != 1) {
                    fprintf(stderr, "badly-formatted uid: %s\n", optarg);
                    return false;
                }
                break;
            default:
                return false;
        }
        last_optind = optind;
    }

    return true;
}

bool check_containers_supported()
{
    fprintf(stderr, "=> validating Linux version...");
    utsname host;
    memset(&host, 0, sizeof(host));
    if (uname(&host)) {
        fprintf(stderr, "failed: %m\n");
        return false;
    }
    int major = -1;
    int minor = -1;
    if (sscanf(host.release, "%u.%u.", &major, &minor) != 2) {
        fprintf(stderr, "weird release format: %s\n", host.release);
        return false;
    }

       // We require kernel 4.7.x or later
    if ((major < 4) || ((major == 4) && (minor < 7))) {
        fprintf(stderr, "expected 4.7.x: %s\n", host.release);
        return false;
    }

    if (strcmp("x86_64", host.machine)) {
        fprintf(stderr, "expected x86_64: %s\n", host.machine);
        return false;
    }
    fprintf(stderr, "%s on %s.\n", host.release, host.machine);

    return true;
}

int run_container(child_config& config)
{
    fprintf(stdout, "Starting container %s\n", config.hostname);

    int err = 0;

    int sockets[2] = { 0 };
    if (socketpair(AF_LOCAL, SOCK_SEQPACKET, 0, sockets)) {
        fprintf(stderr, "socketpair failed: %m\n");
        err = 1;
    } else if (fcntl(sockets[0], F_SETFD, FD_CLOEXEC)) {
        fprintf(stderr, "fcntl failed: %m\n");
        err = 1;
    } else {
        config.fd = sockets[1];


        const size_t STACK_SIZE = 1024 * 1024;
        char* stack = nullptr;
        if (!(stack = (char*)malloc(STACK_SIZE))) {
            fprintf(stderr, "=> malloc failed, out of memory?\n");
            err = 1;
        } else {
            if (resources(config)) {
                err = 1;
            } else {
                   // Run our child process
                const int flags =
                    CLONE_NEWNS |
                    CLONE_NEWCGROUP |
                    CLONE_NEWPID |
                    CLONE_NEWIPC |
                    CLONE_NEWNET |
                    CLONE_NEWUTS;
                const pid_t child_pid = clone(child, stack + STACK_SIZE, flags | SIGCHLD, &config);
                if (child_pid == -1) {
                    fprintf(stderr, "=> clone failed! %m\n");
                    err = 1;
                } else {
                    close(sockets[1]);
                    sockets[1] = 0;
                    close(sockets[1]);
                    sockets[1] = 0;

                    if (!handle_child_uid_map(child_pid, sockets[0])) {
                        err = 1;

                        if (child_pid) kill(child_pid, SIGKILL);
                    }

                    // Wait for the child to exit
                    int child_status = 0;
                    waitpid(child_pid, &child_status, 0);
                    const int return_code = WEXITSTATUS(child_status);

                    // Add it to the error result
                    err |= return_code;

                    fprintf(stdout, "Container %s has exited with return code %d\n", config.hostname, return_code);
                }
            }

            free_resources(config);
            free(stack);
        }
    }

    // Close the sockets
    if (sockets[0] != 0) close(sockets[0]);
    if (sockets[1] != 0) close(sockets[1]);

    return err;
}

}

int main(int argc, char** argv)
{
    child_config config;
    if (!parse_command_line_arguments(argc, argv, config)) {
        print_usage(argv[0]);
        return EX_USAGE;
    } else if (!config.argc) {
        print_usage(argv[0]);
        return EX_USAGE;
    } else if (config.hostname[0] == 0) {
        print_usage(argv[0]);
        return EX_USAGE;
    } else if (config.mount_dir[0] == 0) {
        print_usage(argv[0]);
        return EX_USAGE;
    }

    // Check containers are supported
    if (!check_containers_supported()) {
        return EXIT_FAILURE;
    }

    return run_container(config);
}
