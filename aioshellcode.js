/**
 * PS5 AIO Stage-2 Shellcode Loader for WebKit
 * Fetches binaries directly over HTTP from your repository
 */

let BIN_NAME    = "kexp_2026_05_25.bin";
let ELFLDR_NAME = "elfldr-ps5-1360.elf";

let elfldr_addr = 0n;
let elfldr_size = 0n;
let elfldr_data = null;
let allproc     = 0n;
let master_pipe = null;
let victim_pipe = null;

async function fetch_binary(filename) {
    if (typeof fetch === "function") {
        try {
            const res = await fetch(filename, { cache: "no-store" });
            if (res.ok) {
                const buf = await res.arrayBuffer();
                return new Uint8Array(buf);
            }
        } catch (_) {}
    }
    return null;
}

async function map_shellcode(bin_data) {
    const size         = BigInt(bin_data.length);
    const PAGE_SIZE    = 0x4000n;
    const aligned_size = (size + PAGE_SIZE - 1n) & ~(PAGE_SIZE - 1n);

    const fd_buf  = malloc(4n);
    const exec_fd = syscall(SYSCALL.jitshm_create, 0n, aligned_size, 0x7n);
    if (exec_fd < 0n) {
        throw new Error("jitshm_create failed: 0x" + exec_fd.toString(16));
    }

    const entry_addr = syscall(SYSCALL.mmap, 0n, aligned_size, PROT_RWX, MAP_SHARED, exec_fd, 0n);
    if (entry_addr === 0n || entry_addr === BigInt(-1)) {
        throw new Error("mmap failed (size=0x" + aligned_size.toString(16) + ")");
    }

    write_buffer(entry_addr, bin_data);

    await log("Shellcode mapped @ 0x" + entry_addr.toString(16) + " (size: 0x" + aligned_size.toString(16) + ")");
    return entry_addr;
}

async function run_shellcode(entry_addr) {
    const args = malloc(0x28n);
    write32(args + 0x00n, master_pipe[0]);
    write32(args + 0x04n, master_pipe[1]);
    write32(args + 0x08n, victim_pipe[0]);
    write32(args + 0x0Cn, victim_pipe[1]);
    write64(args + 0x10n, allproc);
    write64(args + 0x18n, elfldr_addr);
    write64(args + 0x20n, elfldr_size);

    const thr_handle = malloc(8n);

    await log("Spawning shellcode thread at: 0x" + entry_addr.toString(16));

    const ret = call(Thrd_create, thr_handle, entry_addr, args);
    if (ret !== 0n) {
        throw new Error("Thrd_create failed: 0x" + ret.toString(16));
    }

    const handle = read64(thr_handle);
    await log("Shellcode thread spawned, handle: 0x" + handle.toString(16));

    const ret_val = malloc(8n);
    const join_ret = call(Thrd_join, handle, ret_val);
    if (join_ret !== 0n) {
        throw new Error("Thrd_join failed: 0x" + join_ret.toString(16));
    }

    await log("Shellcode returned: 0x" + read64(ret_val).toString(16));
}

async function load_elfldr() {
    elfldr_data = await fetch_binary(ELFLDR_NAME);
    if (!elfldr_data) {
        throw new Error("elfldr file not found: " + ELFLDR_NAME);
    }

    elfldr_addr = malloc(BigInt(elfldr_data.length));
    write_buffer(elfldr_addr, elfldr_data);
    elfldr_size = BigInt(elfldr_data.length);

    await log("elfldr @ 0x" + elfldr_addr.toString(16) + " size: 0x" + elfldr_size.toString(16));
}

async function load_bin() {
    const bin_data = await fetch_binary(BIN_NAME);
    if (!bin_data) {
        throw new Error("kexp bin file not found: " + BIN_NAME);
    }

    await log("Bin size: " + bin_data.length + " (0x" + bin_data.length.toString(16) + ")");

    const entry_addr = await map_shellcode(bin_data);
    await run_shellcode(entry_addr);

    await log("=== Stage 2 Shellcode Done (elfldr on Port 9021) ===");
}

async function load_aioshellcode(arg_allproc, arg_master_pipe, arg_victim_pipe) {
    allproc     = arg_allproc;
    master_pipe = arg_master_pipe;
    victim_pipe = arg_victim_pipe;

    await log("=== PS5 AIO JB Shellcode (WebKit Port) ===");
    await load_elfldr();
    await load_bin();
}
