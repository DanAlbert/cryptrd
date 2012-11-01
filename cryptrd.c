/*
 * Encrypting RAM disk driver.
 *
 * Authors:
 * 	Dan Albert
 * 	Hannah Adams
 * 	Kellie Suehisa
 *
 * The basis of this driver was taken from the block device example in Linux
 * Device Drivers 3rd Edition, http://lwn.net/Articles/58719/ and
 * http://blog.superpat.com/2010/05/04/a-simple-block-driver-for-linux-kernel-2-6-31/
 */
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/init.h>

#include <linux/kernel.h> /* printk() */
#include <linux/fs.h>     /* everything... */
#include <linux/errno.h>  /* error codes */
#include <linux/types.h>  /* size_t */
#include <linux/vmalloc.h>
#include <linux/genhd.h>
#include <linux/blkdev.h>
#include <linux/hdreg.h>

static int cryptrd_major = 0;
module_param(cryptrd_major, int, 0);

static int logical_block_size = 512;
module_param(logical_block_size, int, 0);

static int nsectors = 1024;
module_param(nsectors, int, 0);

#define KERNEL_SECTOR_SIZE 512

static struct cryptrd_device {
	unsigned long size;
	u8 *data;
	spinlock_t lock;
	struct request_queue *queue;
	struct gendisk *gd;
} dev;

static void cryptrd_transfer(struct cryptrd_device *dev, sector_t sector,
                             unsigned long nsect, char *buffer, int write)
{
	unsigned long offset = sector * logical_block_size;
	unsigned long nbytes = nsect * logical_block_size;

	if ((offset + nbytes) > dev->size) {
		printk (KERN_NOTICE "cryptrd: attempted write beyond end of "
		                    "disk (%ld %ld)\n", offset, nbytes);
		return;
	}

	if (write)
		memcpy(dev->data + offset, buffer, nbytes);
	else
		memcpy(buffer, dev->data + offset, nbytes);
}

static void cryptrd_request(struct request_queue *q)
{
	struct request *req;

	req = blk_fetch_request(q);
	while (req != NULL) {
		if (req == NULL || (req->cmd_type != REQ_TYPE_FS)) {
			printk(KERN_NOTICE "cryptrd: skipping non-fs "
			                   "request\n");
			__blk_end_request_all(req, -EIO);
			continue;
		}

		cryptrd_transfer(&dev, blk_rq_pos(req), blk_rq_cur_sectors(req),
		            req->buffer, rq_data_dir(req));

		if (! __blk_end_request_cur(req, 0)) {
			req = blk_fetch_request(q);
		}
	}
}

int cryptrd_getgeo(struct block_device * block_device, struct hd_geometry * geo)
{
	long size;

	size = dev.size * (logical_block_size / KERNEL_SECTOR_SIZE);
	geo->cylinders = (size & ~0x3f) >> 6;
	geo->heads = 4;
	geo->sectors = 16;
	geo->start = 0;

	return 0;
}

static struct block_device_operations cryptrd_ops = {
		.owner  = THIS_MODULE,
		.getgeo = cryptrd_getgeo
};

static int __init cryptrd_init(void)
{
	dev.size = nsectors * logical_block_size;
	spin_lock_init(&dev.lock);
	dev.data = vmalloc(dev.size);
	if (dev.data == NULL) {
		printk(KERN_WARNING "cryptrd: vmalloc failure\n");
		return -ENOMEM;
	}

	dev.queue = blk_init_queue(cryptrd_request, &dev.lock);
	if (dev.queue == NULL) {
		printk(KERN_WARNING "cryptrd: blk_init_queue failure\n");
		goto out;
	}

	blk_queue_logical_block_size(dev.queue, logical_block_size);

	cryptrd_major = register_blkdev(cryptrd_major, "cryptrd");
	if (cryptrd_major < 0) {
		printk(KERN_WARNING "cryptrd: unable to get major number\n");
		goto out;
	}

	dev.gd = alloc_disk(16);
	if (!dev.gd) {
		printk(KERN_WARNING "cryptrd: alloc_disk failure");
		goto out_unregister;
	}

	dev.gd->major = cryptrd_major;
	dev.gd->first_minor = 0;
	dev.gd->fops = &cryptrd_ops;
	dev.gd->private_data = &dev;
	strcpy(dev.gd->disk_name, "cryptrd0");
	set_capacity(dev.gd, nsectors);
	dev.gd->queue = dev.queue;
	add_disk(dev.gd);

	return 0;

out_unregister:
	unregister_blkdev(cryptrd_major, "cryptrd");
out:
	vfree(dev.data);
	return -ENOMEM;
}

static void __exit cryptrd_exit(void)
{
	del_gendisk(dev.gd);
	put_disk(dev.gd);
	unregister_blkdev(cryptrd_major, "cryptrd");
	blk_cleanup_queue(dev.queue);
	vfree(dev.data);
}

module_init(cryptrd_init);
module_exit(cryptrd_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Dan Albert, Hannah Adams, Kellie Suehisa");
MODULE_DESCRIPTION("Encrypting RAM disk driver");
