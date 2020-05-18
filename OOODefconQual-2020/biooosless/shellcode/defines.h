
#define PORT_FD_BASE           0x03f0
#define PORT_FD_DOR            0x03f2
#define PORT_FD_STATUS         0x03f4
#define PORT_FD_DATA           0x03f5
#define PORT_FD_DIR            0x03f7

#define FLOPPY_SIZE_CODE 0x02 // 512 byte sectors
#define FLOPPY_DATALEN 0xff   // Not used - because size code is 0x02
#define FLOPPY_MOTOR_TICKS 37 // ~2 seconds
#define FLOPPY_FILLBYTE 0xf6
#define FLOPPY_GAPLEN 0x1B
#define FLOPPY_FORMAT_GAPLEN 0x6c
#define FLOPPY_PIO_TIMEOUT 1000
#define FLOPPY_IRQ_TIMEOUT 5000
#define FLOPPY_SPECIFY1 0xAF  // step rate 12ms, head unload 240ms
#define FLOPPY_SPECIFY2 0x02  // head load time 4ms, DMA used
#define FLOPPY_STARTUP_TIME 8 // 1 second

#define FLOPPY_DOR_MOTOR_D     0x80 // Set to turn drive 3's motor ON
#define FLOPPY_DOR_MOTOR_C     0x40 // Set to turn drive 2's motor ON
#define FLOPPY_DOR_MOTOR_B     0x20 // Set to turn drive 1's motor ON
#define FLOPPY_DOR_MOTOR_A     0x10 // Set to turn drive 0's motor ON
#define FLOPPY_DOR_MOTOR_MASK  0xf0
#define FLOPPY_DOR_IRQ         0x08 // Set to enable IRQs and DMA
#define FLOPPY_DOR_RESET       0x04 // Clear = enter reset mode, Set = normal operation
#define FLOPPY_DOR_DSEL_MASK   0x03 // "Select" drive number for next access


#define PORT_DMA_ADDR_2        0x0004
#define PORT_DMA_CNT_2         0x0005
#define PORT_DMA1_MASK_REG     0x000a
#define PORT_DMA1_MODE_REG     0x000b
#define PORT_DMA1_CLEAR_FF_REG 0x000c
#define PORT_DMA1_MASTER_CLEAR 0x000d
#define PORT_DMA_PAGE_2        0x0081
#define PORT_DMA2_MASK_REG     0x00d4
#define PORT_DMA2_MODE_REG     0x00d6
#define PORT_DMA2_MASTER_CLEAR 0x00da



#define FCF_WAITIRQ 0x10000
#define FC_CHECKIRQ    (0x08 | (0<<8) | (2<<12))
#define FC_SEEK        (0x0f | (2<<8) | (0<<12) | FCF_WAITIRQ)
#define FC_RECALIBRATE (0x07 | (1<<8) | (0<<12) | FCF_WAITIRQ)
#define FC_READID      (0x4a | (1<<8) | (7<<12) | FCF_WAITIRQ)
#define FC_READ        (0xe6 | (8<<8) | (7<<12) | FCF_WAITIRQ)
#define FC_WRITE       (0xc5 | (8<<8) | (7<<12) | FCF_WAITIRQ)
#define FC_FORMAT      (0x4d | (5<<8) | (7<<12) | FCF_WAITIRQ)
#define FC_SPECIFY     (0x03 | (2<<8) | (0<<12)) 

#define CONFIG_QEMU (1)