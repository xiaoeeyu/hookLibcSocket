function LogPrint(log) {
    var theDate = new Date();
    var time = theDate.toISOString().split('T')[1].replace('Z', '');
    var threadid = Process.getCurrentThreadId();
    console.log(`[${time}] -> threadid:${threadid} -- ${log}`);
}

function isprintable(value) {
    return value >= 32 && value <= 126;
}

function getsocketdetail(fd) {
    var type = Socket.type(fd);
    if (type !== null) {
        var peer = Socket.peerAddress(fd);
        var local = Socket.localAddress(fd);
        return `type:${type}, address:${JSON.stringify(peer)}, local:${JSON.stringify(local)}`;
    }
    return "unknown";
}

function printNativeStack(context, name) {
    var array = Thread.backtrace(context, Backtracer.ACCURATE);
    var first = DebugSymbol.fromAddress(array[0]);
    if (first.toString().indexOf('libopenjdk.so!NET_Send') < 0) {
        var trace = array.map(DebugSymbol.fromAddress).join("\n");
        LogPrint(`-----------start:${name}--------------`);
        LogPrint(trace);
        LogPrint(`-----------end:${name}--------------`);
    }
}

function getip(ip_ptr) {
    return Array.from({ length: 4 }, (_, i) => ptr(ip_ptr.add(i)).readU8()).join('.');
}

function getUdpAddr(addrptr) {
    var port = addrptr.add(2).readU16();
    var ip_addr = getip(addrptr.add(4));
    return `peer:${ip_addr}--port:${port}`;
}

function handleUdp(socketType, sockaddr_in_ptr, sizeofsockaddr_in) {
    var addr_info = getUdpAddr(sockaddr_in_ptr);
    console.log(`this is a ${socketType} udp! -> ${addr_info} --- size of sockaddr_in: ${sizeofsockaddr_in}`);
}

function hooklibc() {
    var libcmodule = Process.getModuleByName("libc.so");
    var recvfrom_addr = libcmodule.getExportByName("recvfrom");
    var sendto_addr = libcmodule.getExportByName("sendto");
    console.log(`${recvfrom_addr} --- ${sendto_addr}`);

    Interceptor.attach(recvfrom_addr, {
        onEnter: function (args) {
            this.arg0 = args[0];
            this.arg1 = args[1];
            this.arg2 = args[2];
            this.arg3 = args[3];
            this.arg4 = args[4];
            this.arg5 = args[5];

            LogPrint("go into libc.so->recvfrom");

            var result = getsocketdetail(this.arg0.toInt32());
            if (result.indexOf("udp") > 0) {
                handleUdp('recvfrom', this.arg4, this.arg5);
            }

            printNativeStack(this.context, "recvfrom");
        },
        onLeave: function (retval) {
            var size = retval.toInt32();
            if (size > 0) {
                var result = getsocketdetail(this.arg0.toInt32());
                console.log(`${result} --- libc.so->recvfrom: ${hexdump(this.arg1, { length: size })}`);
            }
            LogPrint("leave libc.so->recvfrom");
        }
    });

    Interceptor.attach(sendto_addr, {
        onEnter: function (args) {
            this.arg0 = args[0];
            this.arg1 = args[1];
            this.arg2 = args[2];
            this.arg3 = args[3];
            this.arg4 = args[4];
            this.arg5 = args[5];

            LogPrint("go into libc.so->sendto");

            var result = getsocketdetail(this.arg0.toInt32());
            if (result.indexOf("udp") > 0) {
                handleUdp('sendto', this.arg4, this.arg5);
            }

            printNativeStack(this.context, "sendto");
        },
        onLeave: function (retval) {
            var size = this.arg2.toInt32();
            if (size > 0) {
                var result = getsocketdetail(this.arg0.toInt32());
                console.log(`${result} --- libc.so->sendto: ${hexdump(this.arg1, { length: size })}`);
            }
            LogPrint("leave libc.so->sendto");
        }
    });
}

function main() {
    hooklibc();
}

setImmediate(main);
