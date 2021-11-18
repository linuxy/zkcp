const std = @import("std");
const log = std.log.scoped(.zkcp);
const Allocator = std.mem.Allocator;

const assert = std.debug.assert;
const mem = std.mem;
const os = std.os;

pub const log_level: std.log.Level = .info;

//=====================================================================
// KCP BASIC
//=====================================================================
pub const IKCP_RDC_CHK_INTERVAL: u32 = 100;
pub const IKCP_RDC_RTT_LIMIT: u32 = 111;
pub const IKCP_RDC_CLOSE_TRY_THRESHOLD: u32 = 26;
pub const IKCP_RDC_LOSS_RATE_LIMIT: u32 = 5;
pub const IKCP_RTO_NDL: u32 = 30;
pub const IKCP_RTO_MIN: u32 = 100;
pub const IKCP_RTO_DEF: u32 = 200;
pub const IKCP_RTO_MAX: u32 = 60000;
pub const IKCP_CMD_PUSH: u32 = 81;
pub const IKCP_CMD_ACK: u32 = 82;
pub const IKCP_CMD_WASK: u32 = 83;
pub const IKCP_CMD_WINS: u32 = 84;
pub const IKCP_ASK_SEND: u32 = 1;
pub const IKCP_ASK_TELL: u32 = 2;
pub const IKCP_WND_SND: u32 = 32;
pub const IKCP_WND_RCV: u32 = 128;
pub const IKCP_MTU_DEF: u32 = 1400;
pub const IKCP_ACK_FAST: u32 = 3;
pub const IKCP_INTERVAL: u32 = 100;
pub const IKCP_OVERHEAD: u32 = 24;
pub const IKCP_DEADLINK: u32 = 20;
pub const IKCP_THRESH_INIT: u32 = 2;
pub const IKCP_THRESH_MIN: u32 = 2;
pub const IKCP_PROBE_INIT: u32 = 7000;
pub const IKCP_PROBE_LIMIT: u32 = 120000;

pub const IWORDS_BIG_ENDIAN = 0;
pub const IKCP_LOG_OUTPUT = 1;
pub const IKCP_LOG_INPUT = 2;
pub const IKCP_LOG_SEND = 4;
pub const IKCP_LOG_RECV = 8;
pub const IKCP_LOG_IN_DATA = 16;
pub const IKCP_LOG_IN_ACK = 32;
pub const IKCP_LOG_IN_PROBE = 64;
pub const IKCP_LOG_IN_WINS = 128;
pub const IKCP_LOG_OUT_DATA = 256;
pub const IKCP_LOG_OUT_ACK = 512;
pub const IKCP_LOG_OUT_PROBE = 1024;
pub const IKCP_LOG_OUT_WINS = 2048;

pub const snode = "node";
//TODO: Refactor into IKCPB struct?

//---------------------------------------------------------------------
// encode / decode
//---------------------------------------------------------------------
pub inline fn ikcp_encode8u(p: *u8, c: u8) *u8 {
    const p_ref = &p;
    p_ref.* += 1;
    p_ref.* = c;
    return p;
}

pub inline fn ikcp_decode8u(p: *const u8, c: *u8) *const u8 {
    const p_ref = &p;
    p_ref.* += 1;
    c.* = p_ref.*;
    return p;
}

pub inline fn ikcp_encode16u(p: *u8, w: u16) *u8 {
    p.* = w;
    p += 2;
    return p;
}

pub inline fn ikcp_decode16u(p: *const u8, w: *u16) *const u8 {
    w.* = p.*;
    p += 2;
    return p;
}

pub inline fn ikcp_encode32u(p: *u8, l: u32) *u8 {
    p.* = l;
    p += 4;
    return p;
}

pub inline fn ikcp_decode32u(p: [*c]const u8, l: *u32) *const u8 {
    l.* = p.*;
    p += 4;
    return p;
}

pub inline fn _imin_(a: u32, b: u32) u32 {
    return if (a <= b) a else b;
}

pub inline fn _imax_(a: u32, b: u32) u32 {
    return if (a >= b) a else b;
}

pub inline fn _ibound_(lower: u32, middle: u32, upper: u32) u32 {
    return _imin_(_imax_(lower, middle), upper);
}

pub inline fn _itimediff(later: u32, earlier: u32) i32 {
    return later -% earlier;
}
//---------------------------------------------------------------------
// manage segment
//---------------------------------------------------------------------
pub const ikcpcb = IKCPCB;

pub fn ikcp_segment_new(kcp: ?*ikcpcb, size: usize) *IKCPSEG {
    _ = kcp;
    return std.heap.c_allocator.create(@sizeOf(IKCPSEG) + size);
}

pub fn ikcp_segment_delete(kcp: ?*ikcpcb, seg: ?*IKCPSEG) void {
    _ = kcp;
    if (seg) |value| std.heap.c_allocator.destroy(value);
    std.heap.c_allocator.destroy(seg.?);
}

pub fn ikcp_canlog(kcp: ?*ikcpcb, mask: u8) bool {
    if(mask & kcp.?.logmask == 0 or kcp.?.writelog == null) return false;
    return true;
}

pub fn ikcp_output(kcp: ?*ikcpcb, data: ?*const c_void, size: usize) usize {
    assert(kcp != null);
    assert(kcp.?.output != null);
    if(ikcp_canlog(kcp, IKCP_LOG_OUTPUT)) {
        log.info("[RO] {} bytes.", .{size});
    }
    if(size == 0) return 0;
    _ = data;
    return 0;
    //return kcp.?.output(data, size, kcp, kcp.?.user);
}
//---------------------------------------------------------------------
// set output callback, which will be invoked by kcp
//---------------------------------------------------------------------
pub fn ikcp_setoutput(kcp: *ikcpcb, output: ?fn (*const u8, usize, *ikcpcb, ?*c_void) usize) void {
    kcp.*.output = output;
}
//---------------------------------------------------------------------
// create a new kcpcb
//---------------------------------------------------------------------
pub fn ikcp_create(conv: u32, user: ?*c_void) ?*ikcpcb {
    const kcp: ?*ikcpcb = &IKCPCB.init();

    kcp.?.buffer = std.heap.c_allocator.alloc(u8, (kcp.?.mtu + IKCP_OVERHEAD) * 3) catch {
        std.heap.c_allocator.destroy(kcp.?);
        return null;
    };

    iqueue_init(&kcp.?.snd_queue);
    iqueue_init(&kcp.?.rcv_queue);
    iqueue_init(&kcp.?.snd_buf);
    iqueue_init(&kcp.?.rcv_buf);
    kcp.?.conv = conv;
    kcp.?.user = user;
    //more
    
    return kcp;
}
//---------------------------------------------------------------------
// release a new kcpcb
//---------------------------------------------------------------------
pub fn ikcp_release(kcp: ?*ikcpcb) void {
    assert(kcp != null);
    if(kcp != null) {
        var seg: ?*IKCPSEG = undefined;
        while (!((&kcp.?.snd_buf) == (&kcp.?.snd_buf).*.next)) {
            seg = iqueue_entry(kcp.?.snd_buf.next, IKCPSEG, snode);
            iqueue_del(&seg.?.node);
            ikcp_segment_delete(kcp, seg);
        }
        while (!((&kcp.?.rcv_buf) == (&kcp.?.rcv_buf).*.next)) {
            seg = iqueue_entry(kcp.?.snd_buf.next, IKCPSEG, snode);
            iqueue_del(&seg.?.node);
            ikcp_segment_delete(kcp, seg);
        }
        while (!((&kcp.?.snd_queue) == (&kcp.?.snd_queue).*.next)) {
            seg = iqueue_entry(kcp.?.snd_buf.next, IKCPSEG, snode);
            iqueue_del(&seg.?.node);
            ikcp_segment_delete(kcp, seg);
        }
        while (!((&kcp.?.rcv_queue) == (&kcp.?.rcv_queue).*.next)) {
            seg = iqueue_entry(kcp.?.snd_buf.next, IKCPSEG, snode);
            iqueue_del(&seg.?.node);
            ikcp_segment_delete(kcp, seg);
        }
        if (kcp.?.buffer.len != 0) {
            log.info("buffer len: {}", .{kcp.?.buffer.len});
            //std.heap.c_allocator.free(kcp.?.buffer);
        }
        if (kcp.?.acklist.len != 0) {
            log.info("acklist len: {}", .{kcp.?.acklist.len});
            //std.heap.c_allocator.free(kcp.?.acklist);
        }
        kcp.?.nrcv_buf = 0;
        kcp.?.nsnd_buf = 0;
        kcp.?.nrcv_que = 0;
        kcp.?.nsnd_que = 0;
        kcp.?.ackcount = 0;
        kcp.?.buffer = undefined;
        kcp.?.acklist = undefined;
        std.heap.c_allocator.destroy(kcp.?);
    }
}

pub var ikcp_free_hook: ?fn (?*c_void) void = null;
pub extern fn free(__ptr: ?*c_void) void;
pub extern fn memcpy(__dest: ?*c_void, __src: ?*const c_void, __n: c_ulong) ?*c_void;

pub export fn ikcp_recv(kcp: *ikcpcb, arg_buffer: [*c]u8, len: isize) isize {
    var p: ?*IQUEUEHEAD = undefined;
    var ispeek: usize = if(len < 0) 1 else 0;
    var peeksize: isize = undefined;
    var recover: bool = false;
    var seg: ?*IKCPSEG = undefined;
    var length: isize = len;
    var buffer = arg_buffer;

    if(iqueue_is_empty(&kcp.*.rcv_queue))
        return -1;

    if(length < 0) length = -length;

    peeksize = ikcp_peeksize(kcp);

    if(peeksize < 0)
        return -2;

    if(peeksize > length)
        return -3;

    if(kcp.*.nrcv_que >= kcp.*.rcv_wnd)
        recover = true;

    p = kcp.*.rcv_queue.next;
    while(p != (&kcp.*.rcv_queue)) {
        var fragment: usize = undefined;
        seg = iqueue_entry(p, IKCPSEG, snode);//@ptrCast(*IKCPSEG, @alignCast(@import("std").meta.alignment(IKCPSEG), @ptrCast(*u8, @alignCast(@import("std").meta.alignment(u8), @ptrCast(*IKCPSEG, @alignCast(@import("std").meta.alignment(IKCPSEG), p)))) - @intCast(isize, @ptrToInt(&@intToPtr(*IKCPSEG, @as(c_int, 8)).*.node))));
        p = p.?.next;

        if(buffer != null) {
            _ = memcpy(@ptrCast(?*c_void, buffer), @ptrCast(?*const c_void, @ptrCast(*u8, @alignCast(std.meta.alignment(u8), &seg.?.data))), @bitCast(c_ulong, @as(c_ulong, seg.?.len)));
            buffer += seg.?.len;
        }

        length += seg.?.len;
        fragment = seg.?.frg;

        if(ikcp_canlog(kcp, IKCP_LOG_RECV)) {
            log.info("recv sn={}", .{seg.?.sn});
        }

        if(ispeek == 0) {
            iqueue_del(&seg.?.node);
            ikcp_segment_delete(kcp, seg);
            kcp.*.nrcv_que -= 1;
        }

        if(fragment == 0)
            break;
    }

    assert(length == peeksize);

    while(!iqueue_is_empty(&kcp.*.rcv_buf)) {
        seg = iqueue_entry(kcp.*.rcv_buf.next, IKCPSEG, snode);
        if(seg.?.sn == kcp.*.rcv_nxt and kcp.*.nrcv_que < kcp.*.rcv_wnd) {
            iqueue_del(&seg.?.node);
            kcp.*.nrcv_buf -= 1;
            iqueue_add_tail(&seg.?.node, &kcp.*.rcv_queue);
            kcp.*.nrcv_que += 1;
            kcp.*.rcv_nxt += 1;
        } else {
            break;
        }
    }

    if(kcp.*.nrcv_que < kcp.*.rcv_wnd and recover) {
        kcp.*.probe |= IKCP_ASK_TELL;
    }
    
    return length;
}

pub fn ikcp_send(kcp: *ikcpcb, buffer: *const u8, len: isize) isize {
    var seg: ?*IKCPSEG = undefined;
    var count: usize = undefined;
    var i: usize = undefined;

    assert(kcp.*.mss > 0);
    if (len < 0) return -1;

    //1. append to previous segment in streaming mode (if possible)
    if (kcp.*.stream != 0) {
        if (!iqueue_is_empty(&kcp.*.snd_queue)) {
            var old: *IKCPSEG = iqueue_entry(kcp.*.snd_queue.prev, IKCPSEG, snode);
            if (old.*.len < kcp.*.mss) {
                var capacity: isize = kcp.*.mss - old.*.len;
                var extend: isize = if (len < capacity) len else capacity;
                seg = ikcp_segment_new(kcp, old.*.len + extend);

                assert(seg != null);
                if(seg == null)
                    return -2;

                iqueue_add_tail(&seg.*.node, &kcp.*.snd_queue);
                @memcpy(seg.*.data, old.*.data, old.*.len);

                if(buffer) {
                    @memcpy(seg.*.data + old.*.len, buffer, extend);
                    buffer += extend;
                }

                seg.*.len = old.*.len + extend;
                seg.*.frg = 0;
                len -= extend;

                iqueue_del_init(&old.*.node);
                ikcp_segment_delete(kcp, old);
            }
        }
        if(len <= 0) {
            return 0;
        }
    }

    //2.
    if(len <= kcp.*.mss) count = 1
    else count = (len + kcp.*.mss - 1) / kcp.*.mss;

    if(count >= IKCP_WND_RCV) return -2;

    if(count == 0) count = 1;

    //3. fragment
    i = 0;
    while (i < count) : (i += 1) {
        var size: isize = if(len > kcp.*.mss) kcp.*.mss else len;

        seg = ikcp_segment_new(kcp, size);
        assert(seg != null);
        if(seg == null)
            return -2;

        if(buffer and len > 0)
            @memcpy(seg.*.data, buffer, size);

        seg.*.len = size;
        seg.*.frg = if(kcp.*.stream == 0) (count - i - 1) else 0;

        iqueue_init(&seg.*.node);
        iqueue_add_tail(&seg.*.node, &kcp.*.snd_queue);
        kcp.*.nsnd_que += 1;

        if(buffer) {
            buffer += size;
        }
        len -= size;
    }

    return 0;
}
//---------------------------------------------------------------------
// parse ack
//---------------------------------------------------------------------
pub fn ikcp_update_ack(kcp: *ikcpcb, rtt: i32) void {
    var rto: i32 = 0;

    if(kcp.*.rx_srtt == 0) {
        kcp.*.rx_srtt = rtt;
        kcp.*.rx_rttval = rtt / 2;
    } else {
        var delta: u32 = rtt - kcp.*.rx_srtt;
        if(delta < 0) delta = -delta;
        kcp.*.rx_rttval = (3 * kcp.*.rx_rttval + delta) / 4;
        kcp.*.rx_srtt = (7 * kcp.*.rx_srtt + rtt) / 8;
        if(kcp.*.rx_srtt < 1) kcp.*.rx_srtt = 1;
    }
    rto = kcp.*.rx_srtt + _imax_(kcp.*.interval, 4 * kcp.*.rx_rttval);
    kcp.*.rx_rto = _ibound_(kcp.*.rx_minrto, rto, IKCP_RTO_MAX);
}

pub fn ikcp_shrink_buf(kcp: *ikcpcb) void {
    var p: *IQUEUEHEAD = kcp.*.snd_buf.next;
    if(p != &kcp.*.snd_buf) {
        var seg: *IKCPSEG = iqueue_entry(p, IKCPSEG, snode);
        kcp.*.snd_una = seg.*.sn;
    } else {
        kcp.*.snd_una = kcp.*.snd_nxt;
    }
}

pub fn ikcp_parse_ack(kcp: *ikcpcb, sn: u32) void {
    var p: *IQUEUEHEAD = undefined;
    var next: *IQUEUEHEAD = undefined;

    if((_itimediff(sn, kcp.*.snd_una) < 0) or (_itimediff(sn, kcp.*.snd_nxt) >= 0))
        return;

    p = kcp.*.snd_buf.next;
    while (p != (&kcp.*.snd_buf)) : (p = next) {
        var seg: ?*IKCPSEG = null;
        next = p.*.next;
        if(sn == seg.*.sn) {
            iqueue_del(p);
            ikcp_segment_delete(kcp, seg);
            kcp.*.nsnd_buf -= 1;
            break;
        }
        if(_itimediff(sn, seg.*.sn) < 0) {
            break;
        }
    }
}

pub fn ikcp_parse_una(kcp: *ikcpcb, una: u32) void {
    var p: *IQUEUEHEAD = undefined;
    var next: *IQUEUEHEAD = undefined;

    p = kcp.*.snd_buf.next;
    while(p != (&kcp.*.snd_buf)) : (p = next) {
        var seg: ?*IKCPSEG = null; //@ptrCast([*c]IKCPSEG, @alignCast(@import("std").meta.alignment(IKCPSEG), @ptrCast([*c]u8, @alignCast(@import("std").meta.alignment(u8), @ptrCast([*c]IKCPSEG, @alignCast(@import("std").meta.alignment(IKCPSEG), p)))) - @intCast(usize, @ptrToInt(&@intToPtr([*c]IKCPSEG, @as(c_int, 0)).*.node))));
        next = p.*.next;
        if(_itimediff(una, seg.*.sn > 0)) {
            iqueue_del(p);
            ikcp_segment_delete(kcp, seg);
            kcp.*.nsnd_buf -= 1;
        } else {
            break;
        }
    }
}

pub fn ikcp_parse_fastack(kcp: *ikcpcb, sn: u32) void {
    var p: *IQUEUEHEAD = undefined;
    var next: *IQUEUEHEAD = undefined;

    if(_itimediff(sn, kcp.*.snd_una) < 0 or _itimediff(sn, kcp.*.snd_nxt) >= 0)
        return;
    
    p = kcp.*.snd_buf.next;
    while(p != (&kcp.*.snd_buf)) : (p = next) {
        var seg: ?*IKCPSEG = null;
        next = p.*.next;
        if(_itimediff(sn, seg.*.sn < 0)) {
            break;
        } else if(sn != seg.*.sn) {
            seg.*.fastack += 1;
        }
    }
}
//---------------------------------------------------------------------
// ack append
//---------------------------------------------------------------------
pub extern fn abort() noreturn;

pub fn ikcp_ack_push(kcp: *ikcpcb, sn: u32, ts: u32) void {
    var newsize: usize = kcp.*.ackcount + 1;
    var ptr: *u32 = undefined;

    if (newsize > kcp.*.ackblock) {
        var acklist: *u32 = undefined;
        var newblock: usize = undefined;
        {
            newblock = 8;
            while (newblock < newsize) : (newblock <<= 1) {}
        }

        acklist = std.heap.c_allocator.alloc(u32, newblock * 2); //malloc

        if(acklist == null) {
            assert(acklist != null);
            abort();
        }

        if(kcp.*.acklist != null) {
            var x: usize = 0;
            while(x < kcp.*.ackcount) : (x += 1) {
                acklist[x * 2 + 0] = kcp.*.acklist[x * 2 + 0];
                acklist[x * 2 + 1] = kcp.*.acklist[x * 2 + 1];
            }
            std.heap.c_allocator.destroy(kcp.*.acklist);
        }

        kcp.*.acklist = acklist;
        kcp.*.ackblock = newblock;
    }

    ptr = &kcp.*.acklist[kcp.*.ackcount * 2];
    ptr[0] = sn;
    ptr[1] = ts;
    kcp.*.ackcount += 1;
}

pub fn ikcp_ack_get(kcp: *const ikcpcb, p: *u32, sn: *u32, ts: *u32) void {
    if(sn) sn[0] = kcp.*.acklist[p * 2 + 0];
    if(ts) ts[0] = kcp.*.acklist[p * 2 + 1];
}
//---------------------------------------------------------------------
// parse data
//---------------------------------------------------------------------
pub fn ikcp_parse_data(kcp: *ikcpcb, newseg: *IKCPSEG) void {
    var p: *IQUEUEHEAD = undefined;
    var prev: *IQUEUEHEAD = undefined;
    var repeat: bool = false;
    var sn: u32 = newseg.*.sn;

    if(_itimediff(sn, kcp.*.rcv_nxt + kcp.*.rcv_wnd) >= 0 or _itimediff(sn, kcp.*.rcv_nxt) < 0) {
        ikcp_segment_delete(kcp, newseg);
        return;
    }

    p = kcp.*.rcv_buf.prev;
    while(p != (&kcp.*.rcv_buf)) : (p = prev) {
        var seg: ?*IKCPSEG = null; //
        prev = p.*.prev;

        if(seg.*.sn == sn) {
            repeat = true;
            break;
        }
        if(_itimediff(sn, seg.*.sn) > 0) {
            break;
        }
    }

    if(repeat == false) {
        iqueue_init(&newseg.*.node);
        iqueue_add(&newseg.*.node, p);
        kcp.*.nrcv_buf += 1;
    } else {
        ikcp_segment_delete(kcp, newseg);
    }

    while(!iqueue_is_empty(&kcp.*.rcv_buf)) {
        var seg: ?*IKCPSEG = iqueue_entry(kcp.*.rcv_buf.next, IKCPSEG, snode);
        if(seg.?.sn == kcp.*.rcv_nxt and kcp.*.nrcv_que < kcp.*.rcv_wnd) {
            iqueue_del(&seg.*.node);
            kcp.*.nrcv_buf -= 1;
            iqueue_add_tail(&seg.*.node, &kcp.*.rcv_queue);
            kcp.*.nrcv_que += 1;
            kcp.*.rcv_nxt += 1;
        } else {
            break;
        }
    }
}
//---------------------------------------------------------------------
// peek data size
//---------------------------------------------------------------------
pub fn ikcp_peeksize(kcp: ?*const ikcpcb) isize {
    var p: ?*IQUEUEHEAD = undefined;
    var seg: ?*IKCPSEG = undefined;
    var length: isize = 0;

    assert(kcp != null);

    if(iqueue_is_empty(&kcp.?.rcv_queue))
        return -1;

    seg = iqueue_entry(kcp.?.rcv_queue.next, IKCPSEG, snode);
    if(seg.?.frg == 0) return @as(isize, seg.?.len);

    if(kcp.?.nrcv_que < seg.?.frg + 1)
        return -1;

    p = kcp.?.rcv_queue.next;
    while (p != &kcp.?.rcv_queue) : (p = p.?.next) {
        seg = iqueue_entry(p, IKCPSEG, snode);
        length += seg.?.len;
        if (seg.?.frg == 0) break;
    }

    return length;
}

pub fn main() !void {
    var user: u8 = 'm';
    const kcp = ikcp_create(5, &user);
    _ = ikcp_release(kcp);

    log.info("hello {}", .{kcp.?.rdc_check_ts});
}


//---------------------------------------------------------------------
// ikcp_encode_seg
//---------------------------------------------------------------------
pub fn ikcp_encode_seg(ptr: *u8, seg: *const IKCPSEG) *u8 {
    ptr = ikcp_encode32u(ptr, seg.*.conv);
    ptr = ikcp_encode8u(ptr, seg.*.cmd);
    ptr = ikcp_encode8u(ptr, seg.*.frg);
    ptr = ikcp_encode16u(ptr, seg.*.wnd);
    ptr = ikcp_encode32u(ptr, seg.*.ts);
    ptr = ikcp_encode32u(ptr, seg.*.sn);
    ptr = ikcp_encode32u(ptr, seg.*.una);
    ptr = ikcp_encode32u(ptr, seg.*.len);
    return ptr;
}

pub fn ikcp_wnd_unused(kcp: *const ikcpcb) isize {
    if (kcp.*.nrcv_que < kcp.*.rcv_wnd) {
        return kcp.*.rcv_wnd - kcp.*.nrcv_que;
    }
    return 0;
}
//---------------------------------------------------------------------
//	ikcp_flush
//---------------------------------------------------------------------
pub fn ikcp_flush(kcp: *ikcpcb) void {
    var current: u32 = kcp.*.current;
    var buffer: *u8 = kcp.*.buffer;
    var ptr: *u8 = buffer;
    var count: u32 = 0;
    var size: usize = 0;
    var i: usize = 0;
    var resent: bool = false;
    var cwnd: usize = 0;
    var rtomin: u32 = 0;
    var p: *IQUEUEHEAD = undefined;
    var change: u32 = 0;
    var lost: u32 = 0;
    var seg: IKCPSEG = undefined;

    if(kcp.*.updated == 0) return;

    seg.conv = kcp.*.conv;
    seg.cmd = IKCP_CMD_ACK;
    seg.frg = 0;
    seg.wnd = ikcp_wnd_unused(kcp);
    seg.una = kcp.*.rcv_nxt;
    seg.len = 0;
    seg.sn = 0;
    seg.ts = 0;

    count = kcp.*.ackcount;
    while(i < count) : (i += 1) {
        size = ptr - buffer;
        if(size + IKCP_OVERHEAD > kcp.*.mtu) {
            _ = ikcp_output(kcp, @ptrCast(?*const c_void, buffer), size);
            ptr = buffer;
        }
        ikcp_ack_get(kcp, i, &seg.sn, &seg.ts);
        ptr = ikcp_encode_seg(ptr, &seg);
    }

    kcp.*.ackcount = 0;

    if(kcp.*.rmt_wnd == 0) {
        if(kcp.*.probe_wait == 0) {
            kcp.*.probe_wait = IKCP_PROBE_INIT;
            kcp.*.ts_probe = kcp.*.current + kcp.*.probe_wait;
        } else {
            if(_itimediff(kcp.*.current, kcp.*.ts_probe) >= 0) {
                if(kcp.*.probe_wait < IKCP_PROBE_INIT)
                    kcp.*.probe_wait = IKCP_PROBE_INIT;
                kcp.*.probe_wait += kcp.*.probe_wait / 2;
                if(kcp.*.probe_wait > IKCP_PROBE_LIMIT)
                    kcp.*.probe_wait = IKCP_PROBE_LIMIT;
                kcp.*.ts_probe = kcp.*.current + kcp.*.probe_wait;
                kcp.*.probe |= IKCP_ASK_SEND;
            }
        }
    } else {
        kcp.*.ts_probe = 0;
        kcp.*.probe_wait = 0;
    }

    if(kcp.*.probe & IKCP_ASK_SEND) {
        seg.cmd = IKCP_CMD_WINS;
        size = ptr - buffer;
        if(size + IKCP_OVERHEAD > kcp.*.mtu) {
            _ = ikcp_output(kcp, @ptrCast(?*const c_void, buffer), size);
            ptr = buffer;
        }
        ptr = ikcp_encode_seg(ptr, &seg);
    }

    kcp.*.probe = 0;

    cwnd = _imin_(kcp.*.snd_wnd, kcp.*.rmt_wnd);
    if(kcp.*.nocwnd == 0) cwnd = _imin_(kcp.*.cwnd, cwnd);

    while(_itimediff(kcp.*.snd_nxt, kcp.*.snd_una + cwnd) < 0) {
        var newseg: *IKCPSEG = undefined;
        if(iqueue_is_empty(&kcp.*.snd_queue))
            break;

        newseg = iqueue_entry(kcp.*.snd_queue.next, IKCPSEG, snode);

        iqueue_del(&newseg.*.node);
        iqueue_add_tail(&newseg.*.node, &kcp.*.snd_buf);
        kcp.*.nsnd_que -= 1;
        kcp.*.nsnd_buf += 1;

        newseg.*.conv = kcp.*.conv;
        newseg.*.cmd = IKCP_CMD_PUSH;
        newseg.*.wnd = seg.wnd;
        newseg.*.ts = current;
        newseg.*.sn = kcp.*.snd_nxt + 1;
        newseg.*.una = kcp.*.rcv_nxt;
        newseg.*.resendts = current;
        newseg.*.rto = kcp.*.rx_rto;
        newseg.*.fastack = 0;
        newseg.*.xmit = 0;
    }

    resent = if(kcp.*.fastresend > 0) kcp.*.fastresend else 0xffffffff;
    rtomin = if(kcp.*.nodelay == 0) (kcp.*.rx_rto >> 3) else 0;

    p = kcp.*.snd_buf.next;
    while (p != (&kcp.*.snd_buf)) : (p = p.*.next) {
        var segment: *IKCPSEG = iqueue_entry(p, IKCPSEG, snode); //[*c]IKCPSEG = @ptrCast([*c]IKCPSEG, @alignCast(@import("std").meta.alignment(IKCPSEG), @ptrCast([*c]u8, @alignCast(@import("std").meta.alignment(u8), @ptrCast([*c]IKCPSEG, @alignCast(@import("std").meta.alignment(IKCPSEG), p)))) - @intCast(usize, @ptrToInt(&@intToPtr([*c]IKCPSEG, @as(c_int, 0)).*.node))));
        var needsend: bool = false;
        if (segment.*.xmit == 0) {
            needsend = 1;
            segment.*.xmit +%= 1;
            segment.*.rto = kcp.*.rx_rto;
            segment.*.resendts = (current +% segment.*.rto) +% rtomin;
        } else if (_itimediff(current, segment.*.resendts) >= 0) {
            needsend = 1;
            segment.*.xmit +%= 1;
            kcp.*.timeout_resnd_cnt +%= 1;
            if (kcp.*.nodelay == 0) {
                segment.*.rto +%= kcp.*.rx_rto;
            } else {
                segment.*.rto +%= @divTrunc(kcp.*.rx_rto, 2);
            }
            segment.*.resendts = current +% segment.*.rto;
            lost = 1;
        } else if (segment.*.fastack >= resent) {
            needsend = 1;
            segment.*.xmit +%= 1;
            segment.*.fastack = 0;
            segment.*.resendts = current +% segment.*.rto;
            change += 1;
        }
        if (needsend != 0) {
            var size_s: u32 = undefined;
            var need: u32 = undefined;
            segment.*.ts = current;
            segment.*.wnd = seg.wnd;
            segment.*.una = kcp.*.rcv_nxt;
            size_s = ptr - buffer;
            need = IKCP_OVERHEAD +% segment.*.len;
            if ((size_s + need) > kcp.*.mtu) {
                _ = ikcp_output(kcp, @ptrCast(?*const c_void, buffer), size_s);
                kcp.*.snd_sum +%= 1;
                ptr = buffer;
            }
            ptr = ikcp_encode_seg(ptr, segment);
            if (segment.*.len > 0) {
                _ = @memcpy(ptr, segment.*.data, segment.*.len);
                ptr += segment.*.len;
            }
            if (segment.*.xmit >= kcp.*.dead_link) {
                kcp.*.state = -1;
            }
        }
    }

    size = ptr - buffer; //
    if (size > 0) {
        _ = ikcp_output(kcp, @ptrCast(?*const c_void, buffer), size);
        kcp.*.snd_sum +%= 1;
    }
    if (change != 0) {
        var inflight: u32 = kcp.*.snd_nxt -% kcp.*.snd_una;
        kcp.*.ssthresh = inflight / 2;
        if (kcp.*.ssthresh < IKCP_THRESH_MIN) {
            kcp.*.ssthresh = IKCP_THRESH_MIN;
        }
        kcp.*.cwnd = kcp.*.ssthresh +% resent;
        kcp.*.incr = kcp.*.cwnd *% kcp.*.mss;
    }
    if (lost != 0) {
        kcp.*.ssthresh = cwnd / 2;
        if (kcp.*.ssthresh < IKCP_THRESH_MIN) {
            kcp.*.ssthresh = IKCP_THRESH_MIN;
        }
        kcp.*.cwnd = 1;
        kcp.*.incr = kcp.*.mss;
    }
    if (kcp.*.cwnd < 1) {
        kcp.*.cwnd = 1;
        kcp.*.incr = kcp.*.mss;
    }
}

pub fn ikcp_rdc_check(kcp: *ikcpcb) u32 {
    var slap: i32 = _itimediff(kcp.*.current, kcp.*.rdc_check_ts);

    if(slap < 0 and slap > -10000)
        return kcp.*.is_rdc_on;

    kcp.*.rdc_check_ts = kcp.*.current + kcp.*.rdc_check_interval;

    if(kcp.*.snd_sum > 0)
        kcp.*.loss_rate = (1.0 * kcp.*.timeout_resnd_cnt / kcp.*.snd_sum * 100);

    kcp.*.timeout_resnd_cnt = 0;
    kcp.*.snd_sum = 0;

    if (!kcp.*.is_rdc_on and kcp.*.loss_rate >= kcp.*.rdc_loss_rate_limit and kcp.*.rx_srtt >= kcp.*.rdc_rtt_limit) {
        kcp.*.is_rdc_on = 1;
    } else if((kcp.*.is_rdc_on and (kcp.*.loss_rate < kcp.*.rdc_loss_rate_limit or kcp.*.rx_srtt < kcp.*.rdc_rtt_limit)
            and ((&kcp.*.rdc_close_try_times + 1) >= kcp.*.rdc_close_try_threshold))) { //?
        kcp.*.is_rdc_on = 0;
    }
    return kcp.*.is_rdc_on;
}

//---------------------------------------------------------------------
// update state (call it repeatedly, every 10ms-100ms), or you can ask 
// ikcp_check when to call it again (without ikcp_input/_send calling).
// 'current' - current timestamp in millisec. 
//---------------------------------------------------------------------
pub fn ikcp_update(kcp: *ikcpcb, current: u32) void {
    var slap: i32 = 0;

    kcp.*.current = current;

    if(kcp.*.updated == 0) {
        kcp.*.updated = 1;
        kcp.*.ts_flush = kcp.*.current;
    }

    slap = _itimediff(kcp.*.current, kcp.*.ts_flush);

    if(slap >= 10000 or slap < -10000) {
        kcp.*.ts_flush = kcp.*.current;
        slap = 0;
    }

    if(slap >= 0) {
        kcp.*.ts_flush += kcp.*.interval;
        if(_itimediff(kcp.*.current, kcp.*.ts_flush) >= 0) {
            kcp.*.ts_flush = kcp.*.current + kcp.*.interval;
        }
        ikcp_flush(kcp);
    }
}
//---------------------------------------------------------------------
// Determine when should you invoke ikcp_update:
// returns when you should invoke ikcp_update in millisec, if there 
// is no ikcp_input/_send calling. you can call ikcp_update in that
// time, instead of call update repeatly.
// Important to reduce unnacessary ikcp_update invoking. use it to 
// schedule ikcp_update (eg. implementing an epoll-like mechanism, 
// or optimize ikcp_update when handling massive kcp connections)
//---------------------------------------------------------------------
pub fn ikcp_check(kcp: *const ikcpcb, current: u32) u32 {
    var ts_flush: u32 = kcp.*.ts_flush;
    var tm_flush: i32 = 0x7fffffff;
    var tm_packet: i32 = 0x7fffffff;
    var minimal: u32 = 0;
    var p: *IQUEUEHEAD = undefined;

    if(kcp.*.updated == 0) {
        return current;
    }

    if(_itimediff(current, ts_flush) >= 10000 or _itimediff(current, ts_flush) < -10000) {
        ts_flush = current;
    }

    if(_itimediff(current, ts_flush) >= 0) {
        return current;
    }

    tm_flush = _itimediff(ts_flush, current);

    p = kcp.*.snd_buf.next;
    while(p != &kcp.*.snd_buf) : (p = p.*.next) {
        const seg: *IKCPSEG = iqueue_entry(p, IKCPSEG, snode);
        var diff: i32 = _itimediff(seg.*.resendts, current);
        if(diff <= 0) {
            return current;
        }
        if(diff < tm_packet) tm_packet = diff;
    }

    minimal = if(tm_packet < tm_flush) tm_packet else tm_flush;
    if(minimal >= kcp.*.interval) minimal = kcp.*.interval;

    return current + minimal;
}

pub fn ikcp_setmtu(kcp: *ikcpcb, mtu: u32) u32 {
    var buffer: ?*u8 = undefined;

    if ((mtu < 50) or (mtu < IKCP_OVERHEAD))
        return -1;
    buffer = std.heap.c_allocator.alloc(u8, (mtu + IKCP_OVERHEAD) * 3);
    if(buffer == null)
        return -2;
    kcp.*.mtu = mtu;
    kcp.*.mss = kcp.*.mtu -% IKCP_OVERHEAD;
    std.heap.c_allocator.destroy(kcp.*.buffer);
    kcp.*.buffer = buffer;
    return 0;
}

pub fn ikcp_interval(kcp: *ikcpcb, interval: u32) u32 {
    if (interval > 5000) {
        interval = 5000;
    } else if (interval < 10) {
        interval = 10;
    }
    kcp.*.interval = interval;
    return 0;
}

pub fn ikcp_nodelay(kcp: *ikcpcb, nodelay: u32, interval: u32, resend: u8, nc: u8) u32 {
    if(nodelay >= 0) {
        kcp.*.nodelay = nodelay;
        if (nodelay != 0) {
            kcp.*.rx_minrto = IKCP_RTO_NDL;
        } else {
            kcp.*.rx_minrto = IKCP_RTO_MIN;
        }
    }
    if(interval >= 0) {
        if (interval > 5000) {
            interval = 5000;
        } else if (interval < 10) {
            interval = 10;
        }
        kcp.*.interval = interval;
    }
    if(resend >= 0) {
        kcp.*.fastresend = resend;
    }
    if (nc >= 0) {
        kcp.*.nocwnd = nc;
    }
    return 0;
}

pub fn ikcp_wndsize(kcp: ?*ikcpcb, sndwnd: u32, rcvwnd: u32) u32 {
    if (kcp != null) {
        if (sndwnd > 0) {
            kcp.*.snd_wnd = sndwnd;
        }
        if (rcvwnd > 0) {
            kcp.*.rcv_wnd = _imax_(rcvwnd, IKCP_WND_RCV);
        }
    }
    return 0;
}

pub fn ikcp_waitsnd(kcp: *const ikcpcb) u32 {
    return (kcp.*.nsnd_buf +% kcp.*.nsnd_que);
}

pub fn ikcp_getconv(ptr: *const c_void) i32 {
    var conv: i32 = 0;
    ikcp_decode32u(ptr, &conv);
    return conv;
}

pub const IKCPCB = struct {
    const Self = @This();
    
    rdc_check_ts: u32,
    rdc_check_interval: u32,
    rdc_rtt_limit: i32,
    is_rdc_on: i32,
    rdc_close_try_times: i32,
    rdc_close_try_threshold: i32,
    snd_sum: u32,
    timeout_resnd_cnt: u32,
    loss_rate: u32,
    rdc_loss_rate_limit: u32,
    conv: u32,
    mtu: u32,
    mss: u32,
    state: u32,
    snd_una: u32,
    snd_nxt: u32,
    rcv_nxt: u32,
    ssthresh: u32,
    rx_rttval: i32,
    rx_srtt: i32,
    rx_rto: i32,
    rx_minrto: i32,
    snd_wnd: u32,
    rcv_wnd: u32,
    rmt_wnd: u32,
    cwnd: u32,
    probe: u32,
    current: u32,
    interval: u32,
    ts_flush: u32,
    nrcv_buf: u32,
    nsnd_buf: u32,
    nrcv_que: u32,
    nsnd_que: u32,
    nodelay: u32,
    updated: u32,
    ts_probe: u32,
    probe_wait: u32,
    dead_link: u32,
    incr: u32,
    snd_queue: IQUEUEHEAD,
    rcv_queue: IQUEUEHEAD,
    snd_buf: IQUEUEHEAD,
    rcv_buf: IQUEUEHEAD,
    acklist: []u32,
    ackcount: u32,
    ackblock: u32,
    user: ?*c_void,
    buffer: []u8,
    fastresend: c_int,
    nocwnd: c_int,
    stream: c_int,
    logmask: c_int,
    output: ?fn (*IKCPCB, ?*c_void, usize) usize,
    writelog: ?fn (*IKCPCB, ?*c_void, usize) usize,

    pub fn init() IKCPCB {
        return IKCPCB {
            .rdc_check_ts = 0,
            .rdc_check_interval = IKCP_RDC_CHK_INTERVAL,
            .rdc_rtt_limit = IKCP_RDC_RTT_LIMIT,
            .is_rdc_on = 0,
            .rdc_close_try_times = 0,
            .rdc_close_try_threshold = IKCP_RDC_CLOSE_TRY_THRESHOLD,
            .snd_sum = 0,
            .timeout_resnd_cnt = 0,
            .loss_rate = 0,
            .rdc_loss_rate_limit = IKCP_RDC_LOSS_RATE_LIMIT,
            .conv = 0,
            .user = null,
            .snd_una = 0,
            .snd_nxt = 0,
            .rcv_nxt = 0,
            .ts_probe = 0,
            .probe_wait = 0,
            .snd_queue = IQUEUEHEAD {.prev = null, .next = null},
            .rcv_queue = IQUEUEHEAD {.prev = null, .next = null},
            .snd_buf = IQUEUEHEAD {.prev = null, .next = null},
            .rcv_buf = IQUEUEHEAD {.prev = null, .next = null},
            .buffer = undefined,
            .snd_wnd = IKCP_WND_SND,
            .rcv_wnd = IKCP_WND_RCV,
            .rmt_wnd = IKCP_WND_RCV,
            .cwnd = 0,
            .incr = 0,
            .probe = 0,
            .mtu = IKCP_MTU_DEF,
            .mss = IKCP_MTU_DEF - IKCP_OVERHEAD,
            .stream = 0,
            .nrcv_buf = 0,
            .nsnd_buf = 0,
            .nrcv_que = 0,
            .nsnd_que = 0,
            .state = 0,
            .acklist = undefined,
            .ackblock = 0,
            .ackcount = 0,
            .rx_srtt = 0,
            .rx_rttval = 0,
            .rx_rto = IKCP_RTO_DEF,
            .rx_minrto = IKCP_RTO_MIN,
            .current = 0,
            .interval = IKCP_INTERVAL,
            .ts_flush = IKCP_INTERVAL,
            .nodelay = 0,
            .updated = 0,
            .logmask = 0,
            .ssthresh = IKCP_THRESH_INIT,
            .fastresend = 0,
            .nocwnd = 0,
            .dead_link = IKCP_DEADLINK,
            .output = null,
            .writelog = null,
        };
    }
};

pub const IKCPSEG = struct {
    node: IQUEUEHEAD,
    conv: u32,
    cmd: u32,
    frg: u32,
    wnd: u32,
    ts: u32,
    sn: u32,
    una: u32,
    len: u32,
    resendts: u32,
    rto: u32,
    fastack: u32,
    xmit: u32,
    data: [1]u8,
};


//TODO: Refactor into queue struct?
pub const IQUEUEHEAD = struct {
    next: ?*IQUEUEHEAD,
    prev: ?*IQUEUEHEAD,
};

pub const iqueue_head = IQUEUEHEAD;

pub fn iqueue_init(ptr: *IQUEUEHEAD) void {
    ptr.*.next = ptr;
    ptr.*.prev = ptr;
}

pub fn iqueue_is_empty(ptr: *const IQUEUEHEAD) bool {
    return ptr == ptr.*.next;
}

pub fn iqueue_entry(ptr: ?*IQUEUEHEAD, @"type": anytype, member: *const [4:0]u8) ?*IKCPSEG {
    _ = member;
    _ = @"type";
    _ = ptr;
    var seg: ?*IKCPSEG = @ptrCast(*IKCPSEG, @alignCast(std.meta.alignment(IKCPSEG), @ptrCast([*c]u8, @alignCast(std.meta.alignment(u8),
    @ptrCast(*IKCPSEG, @alignCast(std.meta.alignment(IKCPSEG), ptr)))) - @intCast(usize, @ptrToInt(&@intToPtr(*IKCPSEG, @as(c_int, 8)).*.node))));
    return seg;
}

pub fn iqueue_add(node: *IQUEUEHEAD, head: *IQUEUEHEAD) void {
    node.*.prev = head;
    node.*.next = head.*.next;
    head.*.next.*.prev = node;
    head.*.next = node;
}

pub fn iqueue_add_tail(node: *IQUEUEHEAD, head: *IQUEUEHEAD) void {
    node.*.prev = head.*.prev;
    node.*.next = head;
    head.*.prev.?.next = node;
    head.*.prev = node;
}

pub fn iqueue_del(entry: *IQUEUEHEAD) void {
    entry.*.next.?.prev = entry.*.prev;
    entry.*.prev.?.next = entry.*.next;
    entry.*.next = undefined;
    entry.*.prev = undefined;
}

pub fn iqueue_del_init(entry: *const IQUEUEHEAD) void {
    //do while(0) ?
    iqueue_del(entry);
    iqueue_init(entry);
}