/*
 * Encrypting RAM disk driver.
 *
 * Authors:
 * 	Dan Albert
 * 	Hannah Adams
 * 	Kellie Suehisa
 *
 * The basis of this driver was taken from the block device example in Linux
 * Device Drivers 3rd Edition, exerpts from an old version of this project,
 * http://lwn.net/Articles/58719/ and
 * http://blog.superpat.com/2010/05/04/a-simple-block-driver-for-linux-kernel-2-6-31/
 */
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/init.h>
#include <linux/sysfs.h>

#include <linux/kernel.h> /* printk() */
#include <linux/fs.h>     /* everything... */
#include <linux/errno.h>  /* error codes */
#include <linux/types.h>  /* size_t */
#include <linux/vmalloc.h>
#include <linux/genhd.h>
#include <linux/blkdev.h>
#include <linux/hdreg.h>

#include <linux/crypto.h>
#include <linux/scatterlist.h>

#define KERNEL_SECTOR_SIZE 512

#define ENCRYPT 1
#define DECRYPT 0

static int cryptrd_major = 0;
module_param(cryptrd_major, int, 0);

static int logical_block_size = 512;
module_param(logical_block_size, int, 0);

static int nsectors = 1024;
module_param(nsectors, int, 0);

#define KEY_SIZE 32 /* AES has a maximum key size of 256 bits */
static char crypto_key[KEY_SIZE];
static int key_size = 0; /* size of the current key */

ssize_t key_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	printk(KERN_DEBUG "cryptrd: copying key\n");
	return scnprintf(buf, PAGE_SIZE, "%s\n", crypto_key);
}

ssize_t key_store(struct device *dev, struct device_attribute *attr,
                  const char *buf, size_t count)
{
	if (count != 16 && count != 24 && count != 32) {
		printk(KERN_WARNING "cryptrd: invalid key size %d\n", count);
		return -EINVAL;
	}

	printk(KERN_DEBUG "cryptrd: storing key\n");
	snprintf(crypto_key, sizeof(crypto_key), "%.*s",
		 (int)min(count, sizeof(crypto_key) - 1), buf);
	key_size = count;
	return count;
}

DEVICE_ATTR(key, 0600, key_show, key_store);

static void cryptrd_root_dev_release(struct device *dev)
{
}

/* our device for sysfs */
static struct device cryptrd_root_dev = {
	.init_name = "cryptrd",
	.release = cryptrd_root_dev_release,
};

/* the device private data */
static struct cryptrd_device {
	unsigned long size;
	u8 *data;
	spinlock_t lock;
	struct request_queue *queue;
	struct gendisk *gd;
} dev;

static int cryptrd_encrypt(char *input, int input_length, int enc)
{
	char *algo = "ecb(aes)"; /* could be made a module param */
	struct crypto_ablkcipher *tfm;
	struct ablkcipher_request *req;
	struct completion comp;
	struct scatterlist sg[8];
	int ret;

	char iv = 0xc6;

	printk(KERN_DEBUG "cryptrd: %s %d bytes\n",
	                  enc ? "encrypting" : "decrypting",
	                  input_length);

	if (key_size == 0) {
		printk(KERN_NOTICE "cryptrd: no key set\n");
		return -EINVAL;
	}

	init_completion(&comp);

	tfm = crypto_alloc_ablkcipher(algo, 0, 0);
	req = ablkcipher_request_alloc(tfm, GFP_KERNEL);

	crypto_ablkcipher_clear_flags(tfm, ~0);

	crypto_ablkcipher_set_flags(tfm, CRYPTO_TFM_REQ_WEAK_KEY);

	ret = crypto_ablkcipher_setkey(tfm, crypto_key, key_size);
	if (ret < 0) {
		printk(KERN_ERR "cryptrd: setkey error %d\n", ret);
		goto out;
	}

	sg_set_buf(&sg[0], input, input_length);

	ablkcipher_request_set_crypt(req, sg, sg, input_length, iv);

	if (enc == ENCRYPT)
		ret = crypto_ablkcipher_encrypt(req);
	else
		ret = crypto_ablkcipher_decrypt(req);

	switch (ret) {
	case 0:
		break;
	case -EINPROGRESS:
	case -EBUSY:
		ret = wait_for_completion_interruptible(&comp);
		if (!ret) {
			INIT_COMPLETION(comp);
			break;
		}

	default:
		printk(KERN_ERR "cryptrd: crypto failed err=%d\n", enc, ret);
		goto out;
	}

	ret = 0;
out:
	crypto_free_ablkcipher(tfm);
	ablkcipher_request_free(req);

	return ret;
}

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

	char *enc_area = NULL;
	int enc_size = 0;

	req = blk_fetch_request(q);
	while (req != NULL) {
		if (req == NULL || (req->cmd_type != REQ_TYPE_FS)) {
			printk(KERN_NOTICE "cryptrd: skipping non-fs "
			                   "request\n");
			__blk_end_request_all(req, -EIO);
			continue;
		}

		enc_size = blk_rq_cur_sectors(req) * KERNEL_SECTOR_SIZE;
		enc_area = kmalloc(enc_size, GFP_KERNEL);

		if (rq_data_dir(req)) { /* write */
			memcpy(enc_area, req->buffer, enc_size);

			cryptrd_encrypt(enc_area, enc_size, ENCRYPT);

			cryptrd_transfer(&dev, blk_rq_pos(req),
			                 blk_rq_cur_sectors(req),
			                 enc_area, rq_data_dir(req));
		} else { /* read */
			cryptrd_transfer(&dev, blk_rq_pos(req),
			                 blk_rq_cur_sectors(req),
			                 enc_area, rq_data_dir(req));

			cryptrd_encrypt(enc_area, enc_size, DECRYPT);

			memcpy(req->buffer, enc_area, enc_size);
		}

		kfree(enc_area);

		if (!__blk_end_request_cur(req, 0)) {
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

static int cryptrd_sysfs_init(void)
{
	int ret;
	ret = device_register(&cryptrd_root_dev);
	if (ret < 0)
		return ret;

	ret = device_create_file(&cryptrd_root_dev, &dev_attr_key);
	if (ret < 0) {
		device_unregister(&cryptrd_root_dev);
		return ret;
	}

	return 0;
}

static void cryptrd_sysfs_release(void)
{
	device_remove_file(&cryptrd_root_dev, &dev_attr_key);
	device_unregister(&cryptrd_root_dev);
}

static int cryptrd_disk_init(void)
{
	int err = 0;

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
		err = -ENOMEM;
		goto out;
	}

	blk_queue_logical_block_size(dev.queue, logical_block_size);

	cryptrd_major = register_blkdev(cryptrd_major, "cryptrd");
	if (cryptrd_major < 0) {
		printk(KERN_WARNING "cryptrd: unable to get major number\n");
		err = cryptrd_major;
		goto out_queue;
	}

	dev.gd = alloc_disk(16);
	if (!dev.gd) {
		printk(KERN_WARNING "cryptrd: alloc_disk failure");
		err = -ENOMEM;
		goto out_unregister;
	}

	dev.gd->major = cryptrd_major;
	dev.gd->first_minor = 0;
	dev.gd->fops = &cryptrd_ops;
	dev.gd->private_data = &dev;
	strcpy(dev.gd->disk_name, "cryptrd0");
	set_capacity(dev.gd, nsectors);
	dev.gd->queue = dev.queue;

	return 0;

out_unregister:
	unregister_blkdev(cryptrd_major, "cryptrd");
out_queue:
	blk_cleanup_queue(dev.queue);
out:
	vfree(dev.data);
	return -ENOMEM;
}

static void cryptrd_disk_release(void)
{
	del_gendisk(dev.gd);
	put_disk(dev.gd);
	unregister_blkdev(cryptrd_major, "cryptrd");
	blk_cleanup_queue(dev.queue);
	vfree(dev.data);
}

static int __init cryptrd_init(void)
{
	int ret;

	ret = cryptrd_disk_init();
	if (ret < 0)
		goto out;

	ret = cryptrd_sysfs_init();
	if (ret < 0)
		goto out_disk;

	add_disk(dev.gd);

	return 0;

out_disk:
	cryptrd_disk_release();
out:
	return ret;
}

static void __exit cryptrd_exit(void)
{
	cryptrd_sysfs_release();
	cryptrd_disk_release();
}

module_init(cryptrd_init);
module_exit(cryptrd_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Dan Albert, Hannah Adams, Kellie Suehisa");
MODULE_DESCRIPTION("Encrypting RAM disk driver");
