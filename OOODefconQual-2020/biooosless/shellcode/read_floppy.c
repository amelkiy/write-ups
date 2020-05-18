#include "defines.h"
#include "types.h"
#include "x86.h"
#include "block.h"
#include "disk.h"
#include "bda.h"
#include "bregs.h"

#define SEG_BDA      0x0040

#define GET_BDA(var) \
    GET_FARVAR(SEG_BDA, ((struct bios_data_area_s *)0)->var)
#define SET_BDA(var, val) \
    SET_FARVAR(SEG_BDA, ((struct bios_data_area_s *)0)->var, (val))

#define MAKE_FLATPTR(seg,off) ((void*)(((u32)(seg)<<4)+(u32)(off)))

#define GET_FARVAR(seg, var) \
    (*((typeof(&(var)))MAKE_FLATPTR((seg), &(var))))
#define SET_FARVAR(seg, var, val) \
    do { GET_FARVAR((seg), (var)) = (val); } while (0)

#define GET_GLOBALFLAT(var) (var)

#define GET_FLATPTR(ptr) (ptr)

#define FLOPPY_DOR_VAL (*(u32*)(0xc9ff0))

static void *memset(void *s, int c, size_t n);
static void basic_access(struct bregs *regs, struct drive_s *drive_fl, u16 command);
static int send_disk_op(struct disk_op_s *op);
static int floppy_read(struct disk_op_s *op);
static int floppy_dma_cmd(struct disk_op_s *op, int count, int command, u8 *param);
static int floppy_prep(struct drive_s *drive_gf, u8 cylinder);
static int floppy_drive_recal(u8 floppyid);
static int floppy_drive_pio(u8 floppyid, int command, u8 *param);
static int floppy_pio(int command, u8 *param);
static void floppy_disable_controller(void);
static inline u8 floppy_dor_read(void);
static inline void floppy_dor_write(u8 val);
static struct chs_s getLCHS(struct drive_s *drive_fl);
static void disk_ret(struct bregs *regs, u8 code);
static int floppy_wait_irq(void);
static int floppy_enable_controller(void);
static void usleep(u32 count);
static void msleep(u32 count);
static inline void floppy_dor_write(u8 val);
static inline u8 floppy_dor_read(void);
static inline void floppy_dor_mask(u8 off, u8 on);
static char* read_floppy();

__attribute__ ((section ("entry"))) int main (){
    asm volatile("call my_main - .text + 6");
    while(1);
}

void my_main(){
    char *flag = read_floppy();

    int i=0;
    while(*flag){
        *(u16*)(0xb8000 + i) = (0x0F00) | *(flag++);
        i += 2;
    }
    while(1);
}

static char* read_floppy(){
    int i, j;
    char *ptr = (char*)0x7c00;
    for (i=0; i<36; i++){
        struct bregs br;
        
        memset(&br, 0, sizeof(br));
        br.flags = F_IF;
        br.dl = 0;      // drive
        br.es = 0x7c0;  // segment
        br.ah = 2;
        br.al = 1;
        br.cl = i + 1;      // sector
        
        struct drive_s drive_fl; // = getDrive(EXTTYPE_FLOPPY, extdrive);
        
        memset(&drive_fl, 0, sizeof(drive_fl));
        drive_fl.cntl_id = 0; //floppyid;
        drive_fl.type = 0x10; //DTYPE_FLOPPY;
        drive_fl.blksize = 512; //DISK_SECTOR_SIZE;
        drive_fl.floppy_type = 4; //ftype;
        drive_fl.sectors = (u64)-1;
        
        // 4 - 1.44MB, 3.5" - 2 heads, 80 tracks, 18 sectors
        
        drive_fl.lchs.head = 2;
        drive_fl.lchs.cylinder = 80;
        drive_fl.lchs.sector = 18;
        
        SET_BDA(disk_interrupt_flag, 0);
        basic_access(&br, &drive_fl, CMD_READ);

        for(int j=0; j<512; j++){
            if(ptr[j] == 'O' && ptr[j+1] == 'O' && ptr[j+2] == 'O' && ptr[j+3] == '{'){
                return ptr + j;
            }
        }
    }
    return NULL;
}

static void *memset(void *s, int c, size_t n)
{
    while (n)
        ((char *)s)[--n] = c;
    return s;
}

// Get the cylinders/heads/sectors for the given drive.
static struct chs_s getLCHS(struct drive_s *drive_fl)
{
    struct chs_s res = { };

    res.cylinder = GET_FLATPTR(drive_fl->lchs.cylinder);
    res.head = GET_FLATPTR(drive_fl->lchs.head);
    res.sector = GET_FLATPTR(drive_fl->lchs.sector);
    return res;
}

// Perform read/write/verify using old-style chs accesses
static void basic_access(struct bregs *regs, struct drive_s *drive_fl, u16 command)
{
    struct disk_op_s dop;
    dop.drive_fl = drive_fl;
    dop.command = command;

    u8 count = regs->al;
    u16 cylinder = regs->ch | ((((u16)regs->cl) << 2) & 0x300);
    u16 sector = regs->cl & 0x3f;
    u16 head = regs->dh;

    dop.count = count;

    struct chs_s chs = getLCHS(drive_fl);
    u16 nlc=chs.cylinder, nlh=chs.head, nls=chs.sector;

    // translate lchs to lba
    dop.lba = (((((u32)cylinder * (u32)nlh) + (u32)head) * (u32)nls)
               + (u32)sector - 1);

    dop.buf_fl = MAKE_FLATPTR(regs->es, regs->bx);

    //int status = send_disk_op(&dop);
    int status = floppy_read(&dop);
    
    regs->al = dop.count;

    disk_ret(regs, status);
}

static struct chs_s lba2chs(struct disk_op_s *op)
{
    struct chs_s res = { };

    u32 tmp = op->lba;
    u16 nls = GET_GLOBALFLAT(op->drive_fl->lchs.sector);
    res.sector = (tmp % nls) + 1;

    tmp /= nls;
    u16 nlh = GET_GLOBALFLAT(op->drive_fl->lchs.head);
    res.head = tmp % nlh;

    tmp /= nlh;
    res.cylinder = tmp;

    return res;
} 

static int floppy_read(struct disk_op_s *op)
{
    struct chs_s chs = lba2chs(op);
    int ret = floppy_prep(op->drive_fl, chs.cylinder);
    if (ret)
        return ret;

    // send read-normal-data command to controller
    u8 floppyid = GET_GLOBALFLAT(op->drive_fl->cntl_id);
    u8 param[8];
    param[0] = (chs.head << 2) | floppyid; // HD DR1 DR2
    param[1] = chs.cylinder;
    param[2] = chs.head;
    param[3] = chs.sector;
    param[4] = FLOPPY_SIZE_CODE;
    param[5] = chs.sector + op->count - 1; // last sector to read on track
    param[6] = FLOPPY_GAPLEN;
    param[7] = FLOPPY_DATALEN;
    return floppy_dma_cmd(op, op->count * DISK_SECTOR_SIZE, FC_READ, param);
}

static int dma_floppy(u32 addr, int count, int isWrite)
{
    // check for 64K boundary overrun
    u16 end = count - 1;
    u32 last_addr = addr + end;
    if ((addr >> 16) != (last_addr >> 16))
        return -1;

    u8 mode_register = 0x46; // single mode, increment, autoinit disable,
    if (isWrite)
        mode_register = 0x4a;

    outb(0x06, PORT_DMA1_MASK_REG);
    outb(0x00, PORT_DMA1_CLEAR_FF_REG); // clear flip-flop
    outb(addr, PORT_DMA_ADDR_2);
    outb(addr>>8, PORT_DMA_ADDR_2);
    outb(0x00, PORT_DMA1_CLEAR_FF_REG); // clear flip-flop
    outb(end, PORT_DMA_CNT_2);
    outb(end>>8, PORT_DMA_CNT_2);

    // port 0b: DMA-1 Mode Register
    // transfer type=write, channel 2
    outb(mode_register, PORT_DMA1_MODE_REG);

    // port 81: DMA-1 Page Register, channel 2
    outb(addr>>16, PORT_DMA_PAGE_2);

    outb(0x02, PORT_DMA1_MASK_REG); // unmask channel 2

    return 0;
}

static int floppy_dma_cmd(struct disk_op_s *op, int count, int command, u8 *param)
{
    // Setup DMA controller
    int isWrite = command != FC_READ;
    int ret = dma_floppy((u32)op->buf_fl, count, isWrite);
    if (ret)
        return DISK_RET_EBOUNDARY;

    // Invoke floppy controller
    u8 floppyid = GET_GLOBALFLAT(op->drive_fl->cntl_id);
    ret = floppy_drive_pio(floppyid, command, param);
    if (ret)
        return ret;

    // Populate floppy_return_status in BDA
    int i;
    for (i=0; i<7; i++)
        SET_BDA(floppy_return_status[i], param[i]);

    if (param[0] & 0xc0) {
        if (param[1] & 0x02)
            return DISK_RET_EWRITEPROTECT;

        return DISK_RET_ECONTROLLER;
    }

    return DISK_RET_SUCCESS;
}


static int floppy_drive_specify(void)
{
    u8 param[2];
    param[0] = FLOPPY_SPECIFY1;
    param[1] = FLOPPY_SPECIFY2;
    return floppy_pio(FC_SPECIFY, param);
}

static int floppy_prep(struct drive_s *drive_gf, u8 cylinder)
{
    u8 floppyid = GET_GLOBALFLAT(drive_gf->cntl_id);
    if (!(GET_BDA(floppy_recalibration_status) & (1<<floppyid)) ||
        !(GET_BDA(floppy_media_state[floppyid]) & FMS_MEDIA_DRIVE_ESTABLISHED)) {
        // Recalibrate drive.
        int ret = floppy_drive_recal(floppyid);
        if (ret)
            return ret;

        // Sense media.  NO NEED - REMOVED
        
        // Execute a SPECIFY command (sets the Step Rate Time,
        // Head Load Time, Head Unload Time and the DMA enable/disable bit).
        ret = floppy_drive_specify();
        if (ret){
            return ret;
        }
    }

    // Seek to cylinder if needed.
    u8 lastcyl = GET_BDA(floppy_track[floppyid]);
    if (cylinder != lastcyl) {
        u8 param[2];
        param[0] = floppyid;
        param[1] = cylinder;
        int ret = floppy_drive_pio(floppyid, FC_SEEK, param);
        if (ret)
            return ret;
        SET_BDA(floppy_track[floppyid], cylinder);
    }

    return DISK_RET_SUCCESS;
}

static int floppy_drive_recal(u8 floppyid)
{
    // send Recalibrate command to controller
    u8 param[2];
    param[0] = floppyid;
    int ret = floppy_drive_pio(floppyid, FC_RECALIBRATE, param);
    if (ret)
        return ret;

    u8 frs = GET_BDA(floppy_recalibration_status);
    SET_BDA(floppy_recalibration_status, frs | (1<<floppyid));
    SET_BDA(floppy_track[floppyid], 0);
    return DISK_RET_SUCCESS;
}

static int floppy_drive_pio(u8 floppyid, int command, u8 *param)
{
    // Enable controller if it isn't running.
    if (!(floppy_dor_read() & FLOPPY_DOR_RESET)) {
        int ret = floppy_enable_controller();
        if (ret)
            return ret;
    }

    // set the disk motor timeout value of INT 08 to the highest value
    //SET_BDA(floppy_motor_counter, 255);

    // Check if the motor is already running
    u8 motor_mask = FLOPPY_DOR_MOTOR_A << floppyid;
    int motor_already_running = floppy_dor_read() & motor_mask;

    // Turn on motor of selected drive, DMA & int enabled, normal operation
    floppy_dor_write(motor_mask | FLOPPY_DOR_IRQ | FLOPPY_DOR_RESET | floppyid);

    // If the motor was just started, wait for it to get up to speed
    if (!motor_already_running && !CONFIG_QEMU)
        msleep(FLOPPY_STARTUP_TIME * 125);

    // Send command.
    int ret = floppy_pio(command, param);
    //SET_BDA(floppy_motor_counter, FLOPPY_MOTOR_TICKS); // reset motor timeout
    if (ret)
        return ret;

    // Check IRQ command is needed after irq commands with no results
    if ((command & FCF_WAITIRQ) && ((command >> 12) & 0xf) == 0)
        return floppy_pio(FC_CHECKIRQ, param);
    return DISK_RET_SUCCESS;
}

static int floppy_pio(int command, u8 *param)
{
    //dprintf(9, "Floppy pio command %x\n", command);
    // Send command and parameters to controller.
    //u32 end = timer_calc(FLOPPY_PIO_TIMEOUT);
    int send = (command >> 8) & 0xf;
    int i = 0;
    for (;;) {
        u8 sts = inb(PORT_FD_STATUS);
        if (!(sts & 0x80)) {
            /*if (timer_check(end)) {
                warn_timeout();
                floppy_disable_controller();
                return DISK_RET_ETIMEOUT;
            }*/
            //yield();
            continue;
        }
        if (sts & 0x40) {
            floppy_disable_controller();
            return DISK_RET_ECONTROLLER;
        }
        if (i == 0)
            outb(command & 0xff, PORT_FD_DATA);
        else
            outb(param[i-1], PORT_FD_DATA);
        if (i++ >= send)
            break;
    }

    // Wait for command to complete.
    if (command & FCF_WAITIRQ) {
        /*int ret = floppy_wait_irq();
        if (ret)
            return ret;*/
        msleep(1);
    }
    //PRINT(LA);

    // Read response from controller.
    //end = timer_calc(FLOPPY_PIO_TIMEOUT);
    int receive = (command >> 12) & 0xf;
    i = 0;
    for (;;) {
        u8 sts = inb(PORT_FD_STATUS);
        if (!(sts & 0x80)) {
            /*if (timer_check(end)) {
                warn_timeout();
                floppy_disable_controller();
                return DISK_RET_ETIMEOUT;
            }*/
            //yield();
            continue;
        }
        if (i >= receive) {
            if (sts & 0x40) {
                floppy_disable_controller();
                return DISK_RET_ECONTROLLER;
            }
            break;
        }
        if (!(sts & 0x40)) {
            floppy_disable_controller();
            return DISK_RET_ECONTROLLER;
        }
        param[i++] = inb(PORT_FD_DATA);
    }

    return DISK_RET_SUCCESS;
}

static int floppy_wait_irq(void)
{
    u8 frs = GET_BDA(floppy_recalibration_status);
    SET_BDA(floppy_recalibration_status, frs & ~FRS_IRQ);
    //u32 end = timer_calc(FLOPPY_IRQ_TIMEOUT);
    for (;;) {
        /*if (timer_check(end)) {
            warn_timeout();
            floppy_disable_controller();
            return DISK_RET_ETIMEOUT;
        }*/
        frs = GET_BDA(floppy_recalibration_status);
        if (frs & FRS_IRQ)
            break;
        // Could use yield_toirq() here, but that causes issues on
        // bochs, so use yield() instead.
        //yield();
    }

    SET_BDA(floppy_recalibration_status, frs & ~FRS_IRQ);
    return DISK_RET_SUCCESS;
}

static int floppy_enable_controller(void)
{
    //dprintf(2, "Floppy_enable_controller\n");
    // Clear the reset bit (enter reset state), but set 'enable IRQ and DMA'
    floppy_dor_mask(FLOPPY_DOR_RESET, FLOPPY_DOR_IRQ);
    // Real hardware needs a 4 microsecond delay
    usleep(4);
    // Set the reset bit (normal operation) and keep 'enable IRQ and DMA' on
    floppy_dor_mask(0, FLOPPY_DOR_IRQ | FLOPPY_DOR_RESET);
    
    msleep(1);
    int ret;
    /*int ret = floppy_wait_irq();
    if (ret)
        return ret;
    */
    
    // After the interrupt is received, send 4 SENSE INTERRUPT commands to
    // clear the interrupt status for each of the four logical drives,
    // supported by the controller.
    // See section 7.4 - "Drive Polling" of the Intel 82077AA datasheet for
    // a more detailed description of why this voodoo needs to be done.
    // Without this, initialization fails on real controllers (but still works
    // in QEMU)
    u8 param[2];
    int i;
    for (i=0; i<4; i++) {
        ret = floppy_pio(FC_CHECKIRQ, param);
        if (ret)
            return ret;
    }
    return DISK_RET_SUCCESS;
}


static void floppy_disable_controller(void)
{
    //dprintf(2, "Floppy_disable_controller\n");
    // Clear the reset bit (enter reset state) and clear 'enable IRQ and DMA'
    floppy_dor_mask(FLOPPY_DOR_IRQ | FLOPPY_DOR_RESET, 0);
}

static inline void floppy_dor_mask(u8 off, u8 on)
{
    floppy_dor_write((floppy_dor_read() & ~off) | on);
}

static inline u8 floppy_dor_read(void)
{
    //return GET_LOW(FloppyDOR);
    return FLOPPY_DOR_VAL;
}

static inline void floppy_dor_write(u8 val)
{
    outb(val, PORT_FD_DOR);
    //SET_LOW(FloppyDOR, val);
    FLOPPY_DOR_VAL = val;
}


static void disk_ret(struct bregs *regs, u8 code)
{
    if (regs->dl < EXTSTART_HD)
        SET_BDA(floppy_last_status, code);
    else
        SET_BDA(disk_last_status, code);
    if (code)
        set_code_invalid_silent(regs, code);
    else
        set_code_success(regs);
}


/***********************************************************/

static u32 timer_read(void)
{
    return rdtscll() >> *(u8*)(0xFDB82);
}

static u32 timer_calc(u32 msecs)
{
    return timer_read() + ((*(u32*)(0xFDB88)) * msecs);
}

static u32 timer_calc_usec(u32 usecs)
{
    u32 cur = timer_read(), khz = (*(u32*)(0xFDB88));
    if (usecs > 500000)
        return cur + DIV_ROUND_UP(usecs, 1000) * khz;
    return cur + DIV_ROUND_UP(usecs * khz, 1000);
} 

static int timer_check(u32 end)
{
    return (s32)(timer_read() - end) > 0;
}

static void timer_sleep(u32 end)
{
    while (!timer_check(end))
        //yield();
        asm volatile("nop");
} 

static void usleep(u32 count) {
    timer_sleep(timer_calc_usec(count));
}
static void msleep(u32 count) {
    timer_sleep(timer_calc(count));
}
