# สัปดาห์ที่ 13: ตรวจจับและวิเคราะห์แพ็กเก็ตสูญหายในเคอร์เนลด้วย eBPF Dropwatch (kfree_skb)

ยินดีต้อนรับสู่ **Week 13** ของหลักสูตร eBPF Noob to Hero!
ในระบบเครือข่ายโปรดักชัน หนึ่งในคำถามที่ตอบยากที่สุดคือ: **"ทำไมแพ็กเก็ตถึงดรอป และเคอร์เนลสั่งทิ้งมันที่จุดไหน ด้วยสาเหตุอะไร?"**

สัปดาห์นี้เราจะพัฒนาเครื่องมือ **Kernel Dropwatch** ระดับโปรดักชันด้วย Modern eBPF (CO-RE + Ring Buffer) โดยเกาะเข้ากับ Kernel Tracepoint `skb:kfree_skb` เพื่อดึง **`skb_drop_reason`** และ Kernel Instruction Pointer แบบ Zero-Copy

---

## 1. ทฤษฎีและสถาปัตยกรรม (Architecture)

```
[ Ingress Packet ] ---> [ RX Ring ] ---> [ IP Layer ] ---> [ Netfilter / Firewall ]
                                               |                   | (Drop)
                                               v (Drop)            v
                                        +-----------------------------+
                                        |  tracepoint:skb:kfree_skb   |
                                        +-----------------------------+
                                                       |
                                            [ eBPF dropwatch.c ]
                                                       | (bpf_ringbuf)
                                                       v
                                            [ Go Control Plane CLI ]
```

---

## 2. วิธีการคอมไพล์และรัน (Build & Run)

```bash
# คอมไพล์ eBPF bytecode และสร้างไบนารี Go
make generate && make build

# รัน dropwatch เฝ้าระวังแพ็กเก็ตดรอปแบบเรียลไทม์
make run
```
