#!/usr/bin/env python3
import atexit
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from subprocess import DEVNULL, STDOUT

SERVER_IP = "192.168.55.1"
CLIENT_IP = "192.168.55.2"
SSTP_PORT = 4443
PPP_SERVER_IP = "10.0.0.1"
PPP_CLIENT_IP = "10.0.0.2"
NS_NAME = "sstp_bench_client"
VETH_SERV = "veth_serv"
VETH_CLI = "veth_cli"
IFNAME = "ppp-sstp"
CGROUP_PATH = Path("/sys/fs/cgroup/sstp-benchmark")
CERT_PATH = Path("tests/self-signed.pem")


ns_exec = ["ip", "netns", "exec", NS_NAME]


def setup_cgroup():
    if CGROUP_PATH.exists():
        remove_cgroup()
    CGROUP_PATH.mkdir()


def remove_cgroup():
    if not CGROUP_PATH.exists():
        return
    with (CGROUP_PATH / "cgroup.kill").open("w") as f:
        f.write("1")
    time.sleep(0.5)
    CGROUP_PATH.rmdir()


def add_self_to_cgroup():
    with (CGROUP_PATH / "cgroup.procs").open("w") as f:
        f.write(str(os.getpid()))


def popen(cmd, **kwargs):
    # Wrapper for Popen that adds the process to cgroup
    if "preexec_fn" not in kwargs:
        kwargs["preexec_fn"] = add_self_to_cgroup
    return subprocess.Popen(cmd, **kwargs)


def run_cmd(cmd, check=True, shell=False, **kwargs):
    return subprocess.run(cmd, check=check, shell=shell, **kwargs)


def cleanup():
    print("\nCleaning up...")
    remove_cgroup()
    run_cmd(["ip", "netns", "del", NS_NAME], check=False)
    run_cmd(["ip", "link", "del", VETH_SERV], check=False)
    print("Cleanup complete.")


def setup_netns():
    print(f"Setting up network namespace '{NS_NAME}'...")
    run_cmd(["ip", "netns", "add", NS_NAME])
    run_cmd(["ip", "link", "add", VETH_SERV, "type", "veth", "peer", "name", VETH_CLI])
    run_cmd(["ip", "link", "set", VETH_CLI, "netns", NS_NAME])

    # Server side
    run_cmd(["ip", "addr", "add", f"{SERVER_IP}/24", "dev", VETH_SERV])
    run_cmd(["ip", "link", "set", VETH_SERV, "up"])

    # Client side
    run_cmd(ns_exec + ["ip", "addr", "add", f"{CLIENT_IP}/24", "dev", VETH_CLI])
    run_cmd(ns_exec + ["ip", "link", "set", VETH_CLI, "up"])
    run_cmd(ns_exec + ["ip", "link", "set", "lo", "up"])

    # Test connectivity
    res = run_cmd(ns_exec + ["ping", "-c", "1", SERVER_IP], check=False)
    if res.returncode != 0:
        print("Error: Could not ping server from namespace.")
        cleanup()
        sys.exit(1)


def main():
    setup_cgroup()
    atexit.register(cleanup)

    cleanup()
    setup_netns()
    setup_cgroup()

    # Create temp directory for configs & logs
    with tempfile.TemporaryDirectory() as tmpdir:
        print(f"Using temp dir: {tmpdir}")
        tmp = Path(tmpdir)

        # Generate pppd options
        pppd_opts = tmp / "options.sstpd"
        with pppd_opts.open("w") as f:
            f.writelines(
                [
                    f"ifname {IFNAME}\n",
                    "noauth\n",
                    "nodefaultroute\n",
                    "nologfd\n",
                    "debug\n",
                    "noipv6\n",
                ]
            )

        # Launch sstp serveer
        print("Starting sstpd server...")
        sstpd_cmd = [
            "uv",
            "run",
            "sstpd",
            "-l",
            SERVER_IP,
            "-p",
            str(SSTP_PORT),
            "-c",
            str(CERT_PATH),
            "--local",
            PPP_SERVER_IP,
            "--remote",
            "10.0.0.0/24",
            "--range",
            f"{PPP_CLIENT_IP}-{PPP_CLIENT_IP}",
            "--pppd",
            shutil.which("pppd"),
            "--pppd-config",
            str(pppd_opts),
        ]
        server_log = tmp / "server.log"
        server_proc = popen(sstpd_cmd, stdout=server_log.open("w"))
        time.sleep(2)
        if server_proc.poll() is not None:
            print("Error: sstpd failed to start. Check server.log")
            sys.exit(1)

        # Launch sstp client
        print("Starting sstpc client...")
        sstpc_cmd = ns_exec + [
            "sstpc",
            "--log-level",
            "4",
            "--log-stdout",
            "--ca-cert",
            str(CERT_PATH),
            "--cert-warn",
            f"{SERVER_IP}:{SSTP_PORT}",
            "noauth",
            "nologfd",
            "noipdefault",
            "debug",
            "noipv6",
        ]
        client_log = tmp / "client.log"
        popen(sstpc_cmd, stdout=client_log.open("w"), stderr=STDOUT)

        # Wait for PPP interfaces
        print("Waiting for PPP connection establishment...")
        connected = False
        for _ in range(5):
            res_srv = run_cmd(
                ["ip", "addr", "show", IFNAME], check=False, stdout=DEVNULL
            )
            res_cli = run_cmd(
                ns_exec + ["ip", "addr", "show", "ppp0"],
                check=False,
                stdout=DEVNULL,
            )
            if res_srv.returncode == 0 and res_cli.returncode == 0:
                print("Connection established!")
                connected = True
                break
            time.sleep(1)

        if not connected:
            print("Error: Connection timed out.")
            print("Server Log Tail:")
            run_cmd(["tail", "-n", "25", str(server_log)], check=False)
            print("Client Log Tail:")
            run_cmd(["tail", "-n", "25", str(client_log)], check=False)
            sys.exit(1)

        # Run iperf3 server
        print("\nStarting iperf3 benchmark...")
        iperf_srv_cmd = ["iperf3", "-sB", PPP_SERVER_IP]
        popen(iperf_srv_cmd, stdout=DEVNULL, stderr=DEVNULL)
        time.sleep(1)

        # Run iperf3 client
        print(f"Running iperf3 client (Upload) connecting to {PPP_SERVER_IP}...")
        subprocess.run(
            ns_exec + ["iperf3", "-c", PPP_SERVER_IP],
            preexec_fn=add_self_to_cgroup,
        )
        time.sleep(1)
        print(f"\nRunning iperf3 client (Download) connecting to {PPP_SERVER_IP}...")
        subprocess.run(
            ns_exec + ["iperf3", "-Rc", PPP_SERVER_IP],
            preexec_fn=add_self_to_cgroup,
        )

        # Processes are now cleaned up by atexit cleanup() -> remove_cgroup()


if __name__ == "__main__":
    main()
