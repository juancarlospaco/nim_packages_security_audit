#!/usr/bin/env python3
import sys
import subprocess
from ast import literal_eval
from argparse import ArgumentParser
from logging import getLogger, NullHandler
from os.path import splitext, basename
from os import readlink
from os.path import normpath, join
from ptrace.syscall.posix_arg import AT_FDCWD
from sys import _getframe
from collections import OrderedDict
from pwd import getpwuid
from grp import getgrgid
from os.path import exists
from os import O_WRONLY, O_RDWR, O_APPEND, O_CREAT, O_TRUNC
from stat import S_IFCHR, S_IFBLK, S_IFIFO, S_IFSOCK
from os.path import dirname, basename

from ptrace.tools import locateProgram
from ptrace.debugger import ProcessSignal, NewProcessEvent, ProcessExecution, ProcessExit
from ptrace.debugger.child import createChild
from ptrace.debugger.debugger import PtraceDebugger
from ptrace.func_call import FunctionCallOptions
from ptrace.syscall import SYSCALL_REGISTER, RETURN_VALUE_REGISTER, DIRFD_ARGUMENTS
from ptrace.syscall.posix_constants import SYSCALL_ARG_DICT
from ptrace.syscall.syscall_argument import ARGUMENT_CALLBACK

SYSCALL_FILTERS = OrderedDict()


def register_filter(syscall, filter_function, filter_scope=None):
    if filter_scope is None:
        # Source: http://stackoverflow.com/a/5071539
        caller_module = _getframe(1).f_globals["__name__"]
        filter_scope = caller_module.split(".")[-1]
    if filter_scope not in SYSCALL_FILTERS:
        SYSCALL_FILTERS[filter_scope] = {}
    SYSCALL_FILTERS[filter_scope][syscall] = filter_function


def filter_change_owner(path, owner, group):
    if owner == -1:
        label = "change group"
        owner = getgrgid(group)[0]
    elif group == -1:
        label = "change owner"
        owner = getpwuid(owner)[0]
    else:
        label = "change owner"
        owner = getpwuid(owner)[0] + ":" + getgrgid(group)[0]
    return f"{label} of {path} to {owner}", 0

register_filter("chown", lambda process, args:
                filter_change_owner(process.full_path(args[0]), args[1], args[2]))
register_filter("fchown", lambda process, args:
                filter_change_owner(process.descriptor_path(args[0]), args[1], args[2]))
register_filter("lchown", lambda process, args:
                filter_change_owner(process.full_path(args[0]), args[1], args[2]))
register_filter("fchownat", lambda process, args:
                filter_change_owner(process.full_path(args[1], args[0]), args[2], args[3]))


def format_permissions(permissions):
    result = ""
    for i in range(2, -1, -1):
        result += "r" if permissions & (4 * 8**i) else "-"
        result += "w" if permissions & (2 * 8**i) else "-"
        result += "x" if permissions & (1 * 8**i) else "-"
    return result

def filter_change_permissions(path, permissions):
    return f"change permissions of {path} to {format_permissions(permissions)}", 0

register_filter("chmod", lambda process, args:
                filter_change_permissions(process.full_path(args[0]), args[1]))
register_filter("fchmod", lambda process, args:
                filter_change_permissions(process.descriptor_path(args[0]), args[1]))
register_filter("fchmodat", lambda process, args:
                filter_change_permissions(process.full_path(args[1], args[0]), args[2]))


def filter_create_directory(path):
    return f"create directory {path}", 0

register_filter("mkdir", lambda process, args:
                filter_create_directory(process.full_path(args[0])))
register_filter("mkdirat", lambda process, args:
                filter_create_directory(process.full_path(args[1], args[0])))


def filter_create_link(path_source, path_target, symbolic):
    label = "create symbolic link" if symbolic else "create hard link"
    return f"{label} from {path_source} to {path_target}", 0

register_filter("link", lambda process, args:
                filter_create_link(process.full_path(args[1]), process.full_path(args[0]), False))
register_filter("linkat", lambda process, args:
                filter_create_link(process.full_path(args[3], args[2]), process.full_path(args[1], args[0]), False))
register_filter("symlink", lambda process, args:
                filter_create_link(process.full_path(args[1]), process.full_path(args[0]), True))
register_filter("symlinkat", lambda process, args:
                filter_create_link(process.full_path(args[2], args[1]), process.full_path(args[0]), True))


allowed_files = set(["/dev/null", "/dev/zero", "/dev/tty", "/dev/random", "/dev/urandom"])

def filter_open(process, path, flags):
    if path in allowed_files:
        return None, None
    if (flags & O_CREAT) and not exists(path):
        operation = f"create file {path}"
    elif (flags & O_TRUNC) and exists(path):
        operation = f"truncate file {path}"
    else:
        operation = None
    if (flags & O_WRONLY) or (flags & O_RDWR) or (flags & O_APPEND) or (operation is not None):
        return_value = process.register_path(path)
    else:
        return_value = None
    return operation, return_value

def filter_mknod(path, type):
    if exists(path):
        return None, None
    elif (type & S_IFCHR):
        label = "create character special file"
    elif (type & S_IFBLK):
        label = "create block special file"
    elif (type & S_IFIFO):
        label = "create named pipe"
    elif (type & S_IFSOCK):
        label = "create socket"
    else:
        label = "create file"
    return f"{label} {path}", 0

def filter_write(process, file_descriptor, byte_count):
    if process.is_tracked_descriptor(file_descriptor):
        path = process.descriptor_path(file_descriptor)
        return f"write {byte_count} Bytes to {path}", byte_count
    else:
        return None, None

def filter_dup(process, file_descriptor_old, file_descriptor_new=None):
    if process.is_tracked_descriptor(file_descriptor_old):
        return None, process.register_path(process.descriptor_path(file_descriptor_old), file_descriptor_new)
    else:
        return None, None

register_filter("open", lambda process, args:
                filter_open(process, process.full_path(args[0]), args[1]))
register_filter("creat", lambda process, args:
                filter_open(process, process.full_path(args[0]), O_CREAT | O_WRONLY | O_TRUNC))
# register_filter("openat", lambda process, args:
#                 filter_open(process, process.full_path(args[1], args[0]), args[2]))  # I/O Error
register_filter("mknod", lambda process, args:
                filter_mknod(process.full_path(args[0]), args[1]))
register_filter("mknodat", lambda process, args:
                filter_mknod(process.full_path(args[1], args[0]), args[2]))
# register_filter("write", lambda process, args: filter_write(process, args[0], args[2]))  # Error tracing process: invalid syntax <unknown>
register_filter("pwrite", lambda process, args: filter_write(process, args[0], args[2]))
register_filter("writev", lambda process, args: filter_write(process, args[0], args[2]))
register_filter("pwritev", lambda process, args: filter_write(process, args[0], args[2]))
# register_filter("dup", lambda process, args: filter_dup(process, args[0]))  # Useless info
# register_filter("dup2", lambda process, args: filter_dup(process, args[0], args[1]))
# register_filter("dup3", lambda process, args: filter_dup(process, args[0], args[1]))


def filter_delete(path):
    return f"delete {path}", 0

register_filter("unlink", lambda process, args: filter_delete(process.full_path(args[0])))
register_filter("unlinkat", lambda process, args: filter_delete(process.full_path(args[1], args[0])))
register_filter("rmdir", lambda process, args: filter_delete(process.full_path(args[0])))


def filter_move(path_old, path_new):
    if dirname(path_old) == dirname(path_new):
        label = "rename"
        path_new = basename(path_new)
    else:
        label = "move"
    return f"{label} {path_old} to {path_new}", 0

register_filter("rename", lambda process, args:
                filter_move(process.full_path(args[0]), process.full_path(args[1])))
register_filter("renameat", lambda process, args:
                filter_move(process.full_path(args[1], args[0]), process.full_path(args[3], args[2])))
register_filter("renameat2", lambda process, args:
                filter_move(process.full_path(args[1], args[0]), process.full_path(args[3], args[2])))



class Process(object):
    def __init__(self, ptrace_process):
        self._process = ptrace_process
        self._next_file_descriptor = 1000000
        self._file_descriptors = {}

    def register_path(self, path, file_descriptor=None):
        if file_descriptor is None:
            file_descriptor = self._next_file_descriptor
            self._next_file_descriptor += 1
        self._file_descriptors[file_descriptor] = path
        return file_descriptor

    def is_tracked_descriptor(self, file_descriptor):
        return file_descriptor in self._file_descriptors

    def descriptor_path(self, file_descriptor):
        if file_descriptor in self._file_descriptors:
            path = self._file_descriptors[file_descriptor]
        else:
            path = readlink(f"/proc/{self._process.pid}/fd/{file_descriptor}")
        return normpath(path)

    def full_path(self, path, directory_descriptor=AT_FDCWD):
        if directory_descriptor == AT_FDCWD:
            directory = readlink(f"/proc/{self._process.pid}/cwd")
        else:
            directory = self.descriptor_path(directory_descriptor)
        return normpath(join(directory, path))


def parse_argument(argument):
    # createText() uses repr() to render the argument,
    # for which literal_eval() acts as an inverse function
    # (see http://stackoverflow.com/a/24886425)
    argument = literal_eval(argument.createText())
    return argument


def get_operations(debugger, syscall_filters, verbose):
    format_options = FunctionCallOptions(
        replace_socketcall=False,
        string_max_length=4096,
    )

    processes = {}
    operations = []

    while True:
        if not debugger:
            # All processes have exited
            break

        # This logic is mostly based on python-ptrace's "strace" example
        try:
            syscall_event = debugger.waitSyscall()
        except ProcessSignal as event:
            event.process.syscall(event.signum)
            continue
        except NewProcessEvent as event:
            event.process.syscall()
            event.process.parent.syscall()
            continue
        except ProcessExecution as event:
            event.process.syscall()
            continue
        except ProcessExit as event:
            continue

        process = syscall_event.process
        syscall_state = process.syscall_state

        syscall = syscall_state.event(format_options)

        if syscall and syscall_state.next_event == "exit":
            # Syscall is about to be executed (just switched from "enter" to "exit")
            if syscall.name in syscall_filters:
                print(syscall.format())

                filter_function = syscall_filters[syscall.name]
                if process.pid not in processes:
                    processes[process.pid] = Process(process)
                arguments = [parse_argument(argument) for argument in syscall.arguments]

                operation, return_value = filter_function(processes[process.pid], arguments)

                if operation is not None:
                    operations.append(operation)

                # if return_value is not None:
                #     # Set invalid syscall number to prevent call execution
                #     process.setreg(SYSCALL_REGISTER, -1)
                #     # Substitute return value to make syscall appear to have succeeded
                #     process.setreg(RETURN_VALUE_REGISTER, return_value)
            #print(syscall.format())  # Usually just close() calls, kinda useless

        process.syscall()

    return operations


def main():
    sys.argv = sys.argv[1:]
    filter_scopes = SYSCALL_FILTERS.keys()
    syscall_filters = {}

    for filter_scope in SYSCALL_FILTERS:
        if filter_scope in filter_scopes:
            for syscall in SYSCALL_FILTERS[filter_scope]:
                syscall_filters[syscall] = SYSCALL_FILTERS[filter_scope][syscall]

    # Suppress logging output from python-ptrace
    getLogger().addHandler(NullHandler())

    # Prevent python-ptrace from decoding arguments to keep raw numerical values
    DIRFD_ARGUMENTS.clear()
    SYSCALL_ARG_DICT.clear()
    ARGUMENT_CALLBACK.clear()

    try:
        sys.argv[0] = locateProgram(sys.argv[0])
        pid = createChild(sys.argv, False)
    except Exception as error:
        print(f"Error executing {sys.argv}: {error}.")
        return 1

    debugger = PtraceDebugger()
    debugger.traceFork()
    debugger.traceExec()

    process = debugger.addProcess(pid, True)
    process.syscall()

    try:
        operations = get_operations(debugger, syscall_filters, True)
    except Exception as error:
        print(f"Error tracing process: {error}.")
        return 1
    finally:
        # Cut down all processes no matter what happens
        # to prevent them from doing any damage
        debugger.quit()

    if operations:
        for operation in operations:
            print("  " + operation)
    else:
        print(f"Not detected any file system operations from: {sys.argv}")

main()
