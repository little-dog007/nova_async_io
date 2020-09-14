/*
 * BRIEF DESCRIPTION
 *
 * File operations for directories.
 *
 * Copyright 2015-2016 Regents of the University of California,
 * UCSD Non-Volatile Systems Lab, Andiry Xu <jix024@cs.ucsd.edu>
 * Copyright 2012-2013 Intel Corporation
 * Copyright 2009-2011 Marco Stornelli <marco.stornelli@gmail.com>
 * Copyright 2003 Sony Corporation
 * Copyright 2003 Matsushita Electric Industrial Co., Ltd.
 * 2003-2004 (c) MontaVista Software, Inc. , Steve Longerbeam
 * This file is licensed under the terms of the GNU General Public
 * License version 2. This program is licensed "as is" without any
 * warranty of any kind, whether express or implied.
 */
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/aio.h>
#include <linux/bitmap.h>
#include <linux/mm.h>
#include <linux/uio.h>

#include "nova.h"
#include "stats.h"
#include "inode.h"


ssize_t do_nova_cow_file_write_async(struct file *filp, struct page **kaddr,
                                     size_t len, loff_t ppos)
{
    return -EIO;
}
/*
@filp: point to file struct
@kaddr: Virtual address corresponding to buffer
@len: length to write
@ppos : offset of this write
*/
ssize_t do_nova_inplace_file_write_async(struct file *filp, struct page **kaddr,
                                         size_t len, loff_t ppos)
{
    
    struct address_space *mapping = filp->f_mapping;
    struct inode *inode = mapping->host;
    struct nova_inode_info *si = NOVA_I(inode);
    struct nova_inode_info_header *sih = &si->header;
    struct super_block *sb = inode->i_sb;
    struct nova_inode *pi, inode_copy;
    struct nova_file_write_entry *entry;
    struct nova_file_write_entry *entryc, entry_copy;
    struct nova_file_write_entry entry_data;
    struct nova_inode_update update;
    loff_t pos;
    size_t bytes, count, offset, copied, all_copied = 0;
    unsigned long start_blk, total_blocks, num_blocks, ent_blks = 0, blocknr = 0;
    unsigned long remain_len = 0, copied_once = 0, kpage_i = 0, page_offset, new_blocks = 0;
    u64 blk_off, file_size;
    u64 begin_tail = 0;
    u64 epoch_id;
    u32 time = 0;
    int allocate = 0, inplace = 0, step = 0;
    unsigned int data_bits;
    ssize_t ret;
    long status;
    bool hole_fill, update_log = false;
    void *kmem;

    pos = ppos;
    count = len;
    if (filp->f_flags & O_APPEND)
        pos = i_size_read(inode);
    page_offset = pos & (PAGE_SIZE - 1);
    total_blocks =  DIV_ROUND_UP(count+page_offset, PAGE_SIZE);

    pi = nova_get_block(sb, sih->pi_addr);
    if (nova_check_inode_integrity(sb, sih->ino, sih->pi_addr, sih->alter_pi_addr, &inode_copy, 0) < 0)
    {
        ret = -EIO;
        goto out;
    }
 
    /* Does file_remove_privs need a lock ? */
    ret = file_remove_privs(filp); 
    if (ret)
        goto out;

    /* maybe we should hold a lock */
    epoch_id = nova_get_epoch_id(sb);

    nova_dbg("%s: epoch_id %llu, inode %lu, offset %lld, count %lu\n",
             __func__, epoch_id, inode->i_ino, pos, count);
    
    num_blocks = total_blocks;
    while (num_blocks > 0)
    {
        hole_fill = false;
        /* offset of actual file block*/
        offset = pos & (nova_inode_blk_size(sih) - 1);
        start_blk = pos >> sb->s_blocksize_bits;
        ent_blks = nova_check_existing_entry(sb, inode, num_blocks,
                                             start_blk, &entry, &entry_copy,
                                             1, epoch_id, &inplace, 1);
        entryc = (metadata_csum == 0) ? entry : &entry_copy;
        if (entry && inplace)
        {
            blocknr = get_nvmm(sb, sih, entryc, start_blk);
            blk_off = blocknr << PAGE_SHIFT;
            allocate = ent_blks;
            nova_info("%s :has found entry, blocknum : %d,blocknr: %lu\n",__func__,allocate,blocknr);
            if (data_csum || data_parity)
                nova_set_write_entry_updating(sb, entry, 1);
        }
        else
        {
            /* allocate blocks to fill hole*/
            /* notice:we don't have a lock,because per_cpu have a free_list.but if 
               current cpu has no free block,should we have to hold a lock?
            */
            allocate = nova_new_data_blocks(sb, sih, &blocknr,
                                            start_blk, ent_blks, ALLOC_NO_INIT,
                                            ANY_CPU, ALLOC_FROM_HEAD);
            nova_dbg("%s: alloc %d blocks,size : %lu @ %lu\n",
                     __func__, allocate,allocate*4096, blocknr);
            if (allocate <= 0)
            {
                nova_dbg("%s alloc blocks failed !% d\n", __func__, allocate);
                ret = allocate;
                goto out;
            }
            hole_fill = true;
            new_blocks += allocate;
            blk_off = nova_get_block_off(sb, blocknr, sih->i_blk_type);
            
        }
        step++;
        bytes = sb->s_blocksize * allocate - offset;
        if (bytes > count)
            bytes = count;
        kmem = nova_get_block(inode->i_sb, blk_off);

        if (hole_fill &&
            (offset || ((offset + bytes) & (PAGE_SIZE - 1)) != 0))
        {
            nova_info("%s :we should handle_head_tail_blocks!\n",__func__);
            ret = nova_handle_head_tail_blocks(sb, inode,
                                               pos, bytes, kmem);
            if (ret)
                goto out;
        }

        /*now copy from user buf*/
        // NOVA_START_TIMING(memcpy_w_nvmm_t, memcpy_time);

        nova_memunlock_range(sb, kmem + offset, bytes);
        /*maybe offset  > page_offset*/
        page_offset = offset & (PAGE_SIZE - 1);
        remain_len = bytes;

        int nums = 0;
        while (remain_len > 0)
        {
            /*copied_once should not lengther than PAGE_SIZE*/
            copied_once = ((remain_len - 1) & (PAGE_SIZE - 1)) + 1 - page_offset;

            copied = copied_once - memcpy_to_pmem_nocache(kmem + offset, kaddr[kpage_i] + page_offset, copied_once);
            
            ++nums;
            all_copied += copied;
            remain_len -= copied;
            offset += copied;
            page_offset = (page_offset + copied) & (PAGE_SIZE - 1);
            
            

            if (copied_once == 0)
            {
                nova_dbg("%s : copied_once is zero!, remain_len is %lu\n", __func__,remain_len);
                break;
            }
            else
            {
                if (remain_len & (PAGE_SIZE - 1) == 0)
                    kpage_i++;
            }
        }
        nova_info("%s :nums: %d\n",__func__,nums);
        nova_memlock_range(sb, kmem + offset-all_copied, bytes);
        //NOVA_END_TIMING(memcpy_w_nvmm_t, memcpy_time);

        if (pos + all_copied > inode->i_size)
            file_size = cpu_to_le64(pos + all_copied);
        else
            file_size = cpu_to_le64(inode->i_size);

        if (hole_fill)
        {
            /* if this write need to append write_entry(alloc new block),the situation is complex
               1.we do not want other write_entry append in the same place
               2.Even if we solved the first problem,when we has a error during writting ,we need to 
                 clear this incomplete write
               so (append write_entry) should hold a lock all the time 
            */
            if (!update_log)
            {
                spin_lock(&inode->i_lock);
                update_log = true;
            }

            update.tail = sih->log_tail;
            update.alter_tail = sih->alter_log_tail;

            // fix me ,time always is zero
            nova_init_file_write_entry(sb, sih, &entry_data,
                                       epoch_id, start_blk, allocate,
                                       blocknr, time, file_size);
            ret = nova_append_file_write_entry(sb, pi, inode, &entry_data, &update);

            if (begin_tail == 0)
                begin_tail = update.curr_entry;
            if (ret)
            {
                nova_dbg("%s: append inode entry failed\n", __func__);
                ret = -ENOSPC;
                goto out;
            }
        }
        else
        {
            /*update existing entry*/
            struct nova_log_entry_info entry_info;
            entry_info.type = FILE_WRITE;
            entry_info.epoch_id = epoch_id;
            entry_info.trans_id = sih->trans_id;
            entry_info.time = time;
            entry_info.file_size = file_size;
            entry_info.inplace = 1;
            nova_inplace_update_write_entry(sb, inode, entry,
                                            &entry_info);
        }
        nova_dbg("Write:%p,%lu\n", kmem, all_copied);
        if (all_copied > 0)
        {
            status = all_copied;
            pos += all_copied;
            count -= all_copied;
            num_blocks -= allocate;
        }
        if (unlikely(all_copied != bytes))
        {
            nova_dbg("%s ERROR!: %p, bytes %lu, copied %lu\n",
                     __func__, kmem, bytes, all_copied);
            if (status >= 0)
                status = -EFAULT;
        }
        if (status < 0)
            break;
    }
    data_bits = blk_type_to_shift[sih->i_blk_type];

    if (update_log)
    {
        nova_memunlock_inode(sb, pi);
        nova_update_inode(sb, inode, pi, &update, 1);
        nova_memlock_inode(sb, pi);
        NOVA_STATS_ADD(inplace_new_blocks, 1);

        /* Update file tree ,we don't need lock*/
        ret = nova_reassign_file_tree(sb, sih, begin_tail);

        if (ret)
            goto out;
    }
    ret = all_copied;
    NOVA_STATS_ADD(inplace_write_breaks, step);
    nova_dbg("blocks: %lu, %lu\n", inode->i_blocks, sih->i_blocks);

    if (!update_log)
    {
        spin_lock(&inode->i_lock);
        sih->i_blocks += (new_blocks << (data_bits - sb->s_blocksize_bits));
        inode->i_blocks = sih->i_blocks;
        inode->i_ctime = inode->i_mtime = current_time(inode);
        
        if (pos > inode->i_size)
        {
            i_size_write(inode, pos);
            sih->i_size = pos;
        }
        sih->trans_id++;
        spin_unlock(&inode->i_lock);
    }else{ /* we already have a lock */
        sih->i_blocks += (new_blocks << (data_bits - sb->s_blocksize_bits));
        nova_info("%s :new_blocks %lu,data_bits :%d,sb->s_blocksize_bits:%d,inode->i_blocks:%d\n",__func__,new_blocks,data_bits,sb->s_blocksize_bits,sih->i_blocks);
        inode->i_blocks = sih->i_blocks;
        inode->i_ctime = inode->i_mtime = current_time(inode);
        
        if (pos > inode->i_size)
        {
            i_size_write(inode, pos);
            sih->i_size = pos;
        }
        sih->trans_id++;
    }

out:
    /*fix this*/
    if (ret < 0)
        nova_cleanup_incomplete_write(sb, sih, blocknr, allocate,
                                      begin_tail, update.tail);
    if(update_log)
        spin_unlock(&inode->i_lock);
    //NOVA_END_TIMING(inplace_write_t, inplace_write_time);
    NOVA_STATS_ADD(inplace_write_bytes, all_copied);
    return ret;
}

/*
@filp: point to file struct
@kaddr: Virtual address corresponding to buffer
@len: length to write
@ppos : offset of this write
*/
ssize_t nova_dax_file_write_async(struct file *filp, struct page **kaddr,
                                  size_t len, loff_t ppos)
{
    struct address_space *mapping = filp->f_mapping;
    struct inode *inode = mapping->host;
    int ret;
    // INIT_TIMING(time);
    if (len == 0)
        return 0;
    //NOVA_START_TIMING(write_t, time);

    if (test_opt(inode->i_sb, DATA_COW))
        do_nova_cow_file_write_async(filp, kaddr, len, ppos);
    else
        do_nova_inplace_file_write_async(filp, kaddr, len, ppos);

    //NOVA_END_TIMING(write_t, time);
    return ret;
}

/*
@filp: point to file struct
@kaddr: Virtual address corresponding to buffer
@len: length to write
@ppos : offset of this write
@nr_segs: use to calculate;while nr_segs == 0 we can call ki_compete
*/
ssize_t nova_dax_file_read_async(struct file *filp, struct page **kaddr,
                                 size_t len, loff_t ppos)
{
    struct inode *inode = filp->f_mapping->host;
    struct super_block *sb = inode->i_sb;
    struct nova_inode_info *si = NOVA_I(inode);
    struct nova_inode_info_header *sih = &si->header;
    struct nova_file_write_entry *entry;
    struct nova_file_write_entry *entryc, entry_copy;
    pgoff_t index, end_index;
    unsigned long offset, page_offset = 0, kpage_i = 0;
    unsigned long copied_once;
    loff_t isize;
    size_t copied = 0, error = -EIO, bytes;
    int rc;
    INIT_TIMING(memcpy_time);

    isize = i_size_read(inode);
    nova_info("%s : inode size :%lu , ppos : %lu\n",__func__,isize,ppos);
    if (!isize || ppos > isize)
        goto out;
    nova_info("%s : len %lu\n",__func__,len);
    if (len <= 0)
        goto out;

    nova_dbg("%s: inode %lu, offset %lu, len %lu, inode->i_size %lu\n",
             __func__, inode->i_ino, ppos, len, isize);

    index = ppos >> PAGE_SHIFT;
    offset = ppos & ~PAGE_MASK;

    if (len > isize - ppos)
        len = isize - ppos;
    entryc = (metadata_csum == 0) ? entry : &entry_copy;
    end_index = (isize - 1) >> PAGE_SHIFT;
    do
    {
        unsigned long nr, left;
        unsigned long nvmm;
        void *dax_mem = NULL;
        int zero = 0;

        if (index >= end_index)
        {
            if (index > end_index)
                goto out;
            nr = ((isize - 1) & ~PAGE_MASK) + 1;
            if (nr <= offset)
                goto out;
        }

        entry = nova_get_write_entry(sb, sih, index);
        if (unlikely(entry == NULL))
        {
            nova_dbgv("Required extent not found: pgoff %lu, inode size %lld\n",
                      index, isize);
            nr = PAGE_SIZE;
            zero = 1;
            goto memcpy;
        }

        if (metadata_csum == 0)
            entryc = entry;
        else if (!nova_verify_entry_csum(sb, entry, entryc))
            return -EIO;

        if (index < entryc->pgoff ||
            index - entryc->pgoff >= entryc->num_pages)
        {
            nova_err(sb, "%s ERROR: %lu, entry pgoff %llu, num %u, blocknr %llu\n",
                     __func__, index, entry->pgoff,
                     entry->num_pages, entry->block >> PAGE_SHIFT);
            return -EINVAL;
        }

        if (entryc->reassigned == 0)
        {
            nr = (entryc->num_pages - (index - entryc->pgoff)) * PAGE_SIZE;
        }
        else
        {
            nr = PAGE_SIZE;
        }
        nvmm = get_nvmm(sb, sih, entryc, index);
        dax_mem = nova_get_block(sb, (nvmm << PAGE_SHIFT));

    memcpy:
        nr = nr - offset;
        if (nr > len - copied)
            nr = len - copied;
        if ((!zero) && (data_csum > 0))
        {
            if (nova_find_pgoff_in_vma(inode, index))
                goto skip_verify;
            if (!nova_verify_data_csum(sb, sih, nvmm, offset, nr))
            {
                nova_err(sb, "%s: nova data checksum and recovery fail! inode %lu, offset %lu, entry pgoff %lu, %u pages, pgoff %lu\n",
                         __func__, inode->i_ino, offset,
                         entry->pgoff, entry->num_pages, index);
                error = -EIO;
                goto out;
            }
        }
    skip_verify:
        //NOVA_START_TIMING(memcpy_r_nvmm_t, memcpy_time);
        page_offset = offset & (PAGE_SIZE - 1);
        if (!zero)
        {
            while (nr > 0)
            {
                if (nr >> PAGE_SHIFT > 0)
                {
                    copied_once = PAGE_SIZE;
                    nr -= PAGE_SIZE;
                }
                else
                {
                    copied_once = nr;
                    nr = 0;
                }

                rc = memcpy_mcsafe(kaddr[kpage_i], dax_mem + offset, copied_once);
                if (rc < 0)
                    goto out;
                copied += copied_once;
                offset += copied_once;
                kpage_i++;
            }
        }
        else
        {
            while (nr > 0)
            {
                if (nr >> PAGE_SHIFT > 0)
                {
                    copied_once = PAGE_SIZE;
                    nr -= PAGE_SIZE;
                }
                else
                {
                    copied_once = nr;
                    nr = 0;
                }

                rc = memset(kaddr[kpage_i], 0, copied_once);
                if (rc < 0)
                    goto out;
                copied += copied_once;
                kpage_i++;
            }
        }

    } while (copied < len);


out:
    if (filp)
        file_accessed(filp);
    NOVA_STATS_ADD(read_bytes, copied);
    nova_dbg("%s return %zu\n", __func__, copied);
    return copied ? copied : error;
}

int sb_init_wq(struct super_block *sb)
{
    struct workqueue_struct *old;
    struct workqueue_struct *wq = alloc_workqueue("dio/%s",
                                                  WQ_UNBOUND | WQ_MEM_RECLAIM | WQ_HIGHPRI, 4,
                                                  sb->s_id);
    if (!wq)
        return -ENOMEM;

    /*
	 * This has to be atomic as more DIOs can race to create the workqueue
	 */
    old = cmpxchg(&sb->s_dio_done_wq, NULL, wq);
    /* Someone created workqueue before us? Free ours... */
    if (old)
        destroy_workqueue(wq);
    return 0;
}
static void queue_wait_work(struct nova_inode_info *ino_info);

void nova_async_work(struct work_struct *p_work)
{

    struct async_work_struct *a_work = container_of(p_work, struct async_work_struct, awork);
    struct file *filp = a_work->a_iocb->ki_filp;
    ssize_t ret = -EINVAL;
    ssize_t written = 0;
    struct iovec *iv = &a_work->my_iov;

    struct pinned_page *pp = (struct pinned_page *)kzalloc(sizeof(struct pinned_page), GFP_KERNEL);
    int j, r;

    unsigned long addr;
    size_t len;
    int n_page;

    down_read(&a_work->tsk->mm->mmap_sem);

    if(!access_ok(iv->iov_base,iv->iov_len)){
        goto quit;
    }

    
    addr = (unsigned long)iv->iov_base;
    len = iv->iov_len + (addr & (PAGE_SIZE - 1));
    addr &= PAGE_MASK;
    

    n_page = DIV_ROUND_UP(len, PAGE_SIZE);
    pp->num = n_page;
    pp->mapped = 0;
    pp->pages = (struct page **)kzalloc(n_page * sizeof(struct page *), GFP_KERNEL);
    pp->kaddr = (struct page **)kzalloc(n_page * sizeof(struct page *), GFP_KERNEL);
   
    
    r = get_user_pages_remote(a_work->tsk, a_work->tsk->mm, addr, n_page, 1, pp->pages, NULL, NULL);

    nova_info("%s :io_work->id:%d,a_work->my_iov.iov_base: %p , len : %lu , addr : %p , n_page: %d , r :%d",__func__,a_work->id,iv->iov_base,len,addr,n_page,r);

    if (r < pp->num)
        pp->num = r;

    for (j = 0; j < pp->num; j++)
        pp->kaddr[j] = kmap(pp->pages[j]);
    
    if (iov_iter_rw(&a_work->iter) == READ)
    {
       /*we need to hold a lock*/
       // inode_lock_shared(inode);
        ret = nova_dax_file_read_async(filp, pp->kaddr,
                                       a_work->my_iov.iov_len,
                                       a_work->ki_pos);

        // inode_unlock_shared(inode);
        if (ret < 0)
            goto out;
        
            
    }

    if (iov_iter_rw(&a_work->iter) == WRITE)
    {
         ret = nova_dax_file_write_async(filp, pp->kaddr, a_work->my_iov.iov_len,
                                        a_work->ki_pos);
       
        if (ret < 0)
            goto out;
    }

    if (iov_iter_rw(&a_work->iter) == READ)
    {
        //set user read buffer pages dirty
        for (j = 0; j < pp->num; j++)
            set_page_dirty(pp->pages[j]);
    }

out:
    for (j = 0; j < pp->num; j++)
    {
        kunmap(pp->pages[j]);
        put_page(pp->pages[j]);
    }
    kfree(pp->pages);
    kfree(pp->kaddr);

    kfree(pp);
    pp = NULL;

quit:
   
    up_read(&a_work->tsk->mm->mmap_sem);


    struct inode *inode = filp->f_mapping->host;
    unsigned long first_blk,nr,wtbit,wkbit;
    struct nova_inode_info *ino_info;
    struct async_work_struct *tmp_contn;
    ino_info = container_of(inode, struct nova_inode_info, vfs_inode);
    struct super_block *sb = ino_info->vfs_inode.i_sb;
    first_blk = a_work->first_blk;
	nr = a_work->blknr;
    //queue work from conflict queue
    if (!list_empty(&a_work->aio_conflicq))
    {
        tmp_contn = container_of(a_work->aio_conflicq.next, struct async_work_struct, aio_conflicq);
        tmp_contn->first_blk = a_work->first_blk;
        tmp_contn->blknr = a_work->blknr;

        spin_lock(&ino_info->aio.wk_bitmap_lock);
        /*use wk_bitmap_lock to achieve atomic*/
        if (--(*(a_work->nr_segs)) == 0)
            a_work->a_iocb->ki_complete(a_work->a_iocb, written, 0);
        spin_unlock(&ino_info->aio.wk_bitmap_lock);


        list_del(&a_work->aio_conflicq);
        INIT_WORK(&(tmp_contn->awork), nova_async_work);
        tmp_contn->isQue = queue_work(sb->s_dio_done_wq, &(tmp_contn->awork));
    }
    else
    { 
        //conflict queue empty, clear workbitmap
        wkbit = first_blk;
        spin_lock(&ino_info->aio.wk_bitmap_lock);
        /*use wk_bitmap_lock to achieve atomic*/
        if (--(*(a_work->nr_segs)) == 0)
            a_work->a_iocb->ki_complete(a_work->a_iocb, written, 0);
        nova_info("%s : clear work_bitmap first_blk : %lu,nr :%lu\n",__func__,first_blk,nr);
        for_each_set_bit_from(wkbit, ino_info->aio.work_bitmap, first_blk+nr)
            clear_bit(wkbit, ino_info->aio.work_bitmap);
        spin_unlock(&ino_info->aio.wk_bitmap_lock);
        //check waitqueue
        if (spin_trylock(&inode->i_lock))
        {
            queue_wait_work(ino_info);
            spin_unlock(&inode->i_lock);
        }
    }

    
    kfree(a_work);
    a_work = NULL;
}

static void queue_wait_work(struct nova_inode_info *ino_info)

{
    unsigned long wkbit, size;
    struct super_block *sb = ino_info->vfs_inode.i_sb;
    struct list_head *async_pos;
    struct async_work_struct *contn;

    if (ino_info->aio.i_waitque.next == &ino_info->aio.i_waitque)
        return;
    async_pos = ino_info->aio.i_waitque.next;
    spin_lock(&ino_info->aio.wk_bitmap_lock);
    while (async_pos != &ino_info->aio.i_waitque)
    {
        contn = container_of(async_pos, struct async_work_struct, aio_waitq);
        wkbit = contn->first_blk;
        size = wkbit + contn->blknr;
        wkbit = find_next_bit(ino_info->aio.work_bitmap, size, wkbit);

        if (wkbit >= size)
        {
            nova_info("%s :schedu ino->aio.i_waitque: %d\n",__func__,contn->id);
            nova_info("%s :contn->first_blk:%lu,nr :%lu\n",__func__,contn->first_blk,contn->blknr);
            wkbit = contn->first_blk;
           
            for_each_clear_bit_from(wkbit, ino_info->aio.work_bitmap, size)
                set_bit(wkbit, ino_info->aio.work_bitmap);
            wkbit = contn->first_blk;
            for_each_set_bit_from(wkbit, ino_info->aio.wait_bitmap, size)
                clear_bit(wkbit, ino_info->aio.wait_bitmap);
            INIT_WORK(&(contn->awork), nova_async_work);
            contn->isQue = queue_work(sb->s_dio_done_wq, &(contn->awork));

            async_pos = async_pos->next;
            list_del(&contn->aio_waitq);
        }
        else
            async_pos = async_pos->next;
    }
    spin_unlock(&ino_info->aio.wk_bitmap_lock);
}


/*i had not found the same funtion in kernel functions*/
static inline void list_merge(const struct list_head *list,struct list_head *prev,struct list_head *next)
{
    struct list_head*first = list;
    struct list_head*last = list->prev;

    first->prev = prev;
    prev->next = first;

    last->next = next;
    next->prev = last;
}

/*id for test*/
static int id=0;
ssize_t nova_direct_IO(struct kiocb *iocb, struct iov_iter *iter)
{
    
    struct file *filp = iocb->ki_filp;
    struct inode *inode = filp->f_mapping->host;
    struct iovec *iv = iter->iov;
    struct nova_inode_info *ino_info;
    struct super_block *sb = inode->i_sb;
    struct async_work_struct *io_work;

    loff_t end = iocb->ki_pos; /* notice ,we should  not use iter->iov_offset,because iter->iov_offset is always  zero*/
    ssize_t ret = -EINVAL;
    unsigned long seg, nr_segs = iter->nr_segs;
    unsigned long size,i_blocks;  /* support maximum file size is 4G */

    
    ino_info = container_of(inode, struct nova_inode_info, vfs_inode);
    
    for (seg = 0; seg < nr_segs; seg++)
    {
        end += iv->iov_len;
        iv++;
    }
    iv = iter->iov;
   // nova_info("iocb->pos: %ld, iter->iov_offset: %ld, end : %lu\n",iocb->ki_pos,iter->iov_offset,end);

    if (!is_sync_kiocb(iocb))
    {
       // nova_info("async\n");
        
      
        if (!sb->s_dio_done_wq)
            ret = sb_init_wq(sb);
        spin_lock(&inode->i_lock);

        if(iocb->ki_pos > inode->i_size){
            nova_info("%s: iocb->ki_pos is too big !\n",__func__);
            spin_unlock(&inode->i_lock);
            return ret;
        }
            
        size =  end;
        i_blocks = inode->i_blocks;/*inode->i_blocks is  4kb*/
        if (size < inode->i_size)
            size = inode->i_size;
        else{
            if((iov_iter_rw(iter) == WRITE)){
                i_blocks = DIV_ROUND_UP(size,PAGE_SIZE);
            }
        }

        //async bitmap init
        if (!ino_info->aio.wait_bitmap)
        {
            ino_info->aio.wait_bitmap = kzalloc(BITS_TO_LONGS(i_blocks) * sizeof(long), GFP_KERNEL);
            ino_info->aio.work_bitmap = kzalloc(BITS_TO_LONGS(i_blocks) * sizeof(long), GFP_KERNEL);
            ino_info->aio.bitmap_size = BITS_TO_LONGS(i_blocks) * sizeof(long);
            // nova_info("%s :alloc bitmap ino_info->aio.bitmap_size=%lu\n",__func__, ino_info->aio.bitmap_size);
        }
        else
        {
            if (ino_info->aio.bitmap_size * BITS_PER_BYTE < i_blocks)
            {
                unsigned long *tmp = kzalloc(BITS_TO_LONGS(i_blocks) * sizeof(long), GFP_KERNEL);
                memcpy((void *)ino_info->aio.wait_bitmap, (void *)tmp, ino_info->aio.bitmap_size);
                kfree(ino_info->aio.wait_bitmap);
                ino_info->aio.wait_bitmap = tmp;
                tmp = kzalloc(BITS_TO_LONGS(i_blocks) * sizeof(long), GFP_KERNEL);
                memcpy((void *)ino_info->aio.work_bitmap, (void *)tmp, ino_info->aio.bitmap_size);
                kfree(ino_info->aio.work_bitmap);
                ino_info->aio.work_bitmap = tmp;
                ino_info->aio.bitmap_size = BITS_TO_LONGS(i_blocks) * sizeof(long);
               // nova_info("%s :realloc bitmap ino_info->aio.bitmap_size=%d\n",__func__, ino_info->aio.bitmap_size);
            }
        }

        if (!ino_info->aio.wait_bitmap || !ino_info->aio.work_bitmap)
        {
            kfree(ino_info->aio.wait_bitmap);
            kfree(ino_info->aio.work_bitmap);
            ino_info->aio.bitmap_size = 0;
            // nova_info("%s :ino_info->aio.wait_bitmap if free and exit,notice we don't unlock_spinlock!\n",__func__);
            return -ENOMEM;
        }

        // async_work_struct(I/O node in file waitqueue) init

        unsigned long first_blk, nr, off, wtbit, wkbit;
        unsigned long *temp_seg = (unsigned long*)kzalloc(sizeof(unsigned long),GFP_KERNEL);
        *temp_seg = nr_segs; 
        struct list_head *async_pos;
        struct async_work_struct *contn = NULL;
        loff_t pos;

        /*if file need to grow,we should add multiple write request(nr_segs>1)
          to same conflict queue;because we need to ensure atomicity;
        */
        bool need_grow = false; 

        seg = 0;
        end = iocb->ki_pos;
        size = inode->i_size;
        
        while (seg < nr_segs)
        {
            io_work = (struct async_work_struct *)kzalloc(sizeof(struct async_work_struct), GFP_KERNEL);
            pos = end;
            end += iv->iov_len;
            if(end > size){
                if((iov_iter_rw(iter) == WRITE))
                    need_grow = true;
                else{
                    end = size;
                    *temp_seg = seg+1;
                    seg = nr_segs;
                }
            }
            
            
            
            memcpy(&io_work->iter,iter,sizeof(struct iov_iter));
            io_work->id = id++;
            io_work->my_iov.iov_base = iv->iov_base;
            io_work->my_iov.iov_len = end-pos;
            io_work->ki_pos = pos;
            io_work->a_iocb = iocb;
            io_work->nr_segs = temp_seg;
            io_work->tsk = current;
            io_work->isQue = 0;
            INIT_LIST_HEAD(&io_work->aio_waitq);
            INIT_LIST_HEAD(&io_work->aio_conflicq);

            first_blk = pos >> PAGE_SHIFT; // notice: if end =0;first_blk == 0?
            off = pos & (PAGE_SIZE-1);
            nr = DIV_ROUND_UP( iv->iov_len+ off, PAGE_SIZE);
            io_work->first_blk = first_blk;
            io_work->blknr = nr;
            nova_info("%s: io_work : %d,io_work->my_iov.iov_bashe:%p , io_work->my_iov.iov_len : %lu,io_work->ki_pos:%lu\n",
                        __func__ ,io_work->id,io_work->my_iov.iov_base,io_work->my_iov.iov_len,io_work->ki_pos);


            iv++;
            seg++;
                   
            if(need_grow){
                if(contn == NULL){
                    contn = io_work;
                    }
                else{
                    /*if file need to grow,we should add multiple write request(nr_segs>1)
                      to same conflict queue;because we need to ensure atomicity;
                    */
                    list_add_tail(&io_work->aio_conflicq,&contn->aio_conflicq);
                    // nova_info("%s :conflicq queue: head id: %d add id: %d ",__func__,contn->id,io_work->id);
                }


                if(seg == nr_segs){
                    /*for file grow , we should update inode->i_size first*/
                    inode->i_size = end;

                    first_blk = contn->first_blk;
                    nr = DIV_ROUND_UP(end - contn->ki_pos,PAGE_SIZE);
                    io_work = contn;
                    io_work->blknr = nr;
                    
                    /* for test*/
                    nova_info("%s : conficq queue : ",__func__);
                    struct async_work_struct *head = contn;
                    do{
                        nova_info("%d -->",head->id);
                        head = container_of(head->aio_conflicq.next, struct async_work_struct,aio_conflicq);
                    }while(head != contn);
                    nova_info("tail \n");
                    /* for test*/
                }
                else
                    continue;
                
            }

            /*for test*/
            wtbit = first_blk;
            wtbit = find_next_bit(ino_info->aio.wait_bitmap, first_blk + nr , wtbit);
            wkbit = first_blk;
            wkbit = find_next_bit(ino_info->aio.work_bitmap, first_blk + nr, wkbit);
            // nova_info("%s : io_work->id:%d,wtbit:%lu,wkbit : %lu\n",__func__,io_work->id,wtbit,wkbit);
            
            if (wtbit < first_blk + nr || wkbit < first_blk + nr)
            {
                if (wtbit >= first_blk + nr)
                { // 01
                    nova_info("first_blk :%lu,nr : %lu\n",first_blk,nr);
                    nova_info("%s : add io_work: %d to ino_info->waitque \n",__func__,io_work->id);
                    wtbit = first_blk;
                    spin_lock(&ino_info->aio.wk_bitmap_lock);
                    for_each_clear_bit_from(wtbit, ino_info->aio.wait_bitmap, first_blk + nr)
                        set_bit(wtbit, ino_info->aio.wait_bitmap);
                    async_pos = ino_info->aio.i_waitque.next;
                    while (async_pos != &ino_info->aio.i_waitque)
                    {
                        contn = container_of(async_pos, struct async_work_struct, aio_waitq);
                        if (contn->first_blk > first_blk)
                            break;
                        async_pos = async_pos->next;
                    }
                    list_add_tail(&io_work->aio_waitq, async_pos);
                    spin_unlock(&ino_info->aio.wk_bitmap_lock);
                }
                else
                { //10 11
                    spin_lock(&ino_info->aio.wk_bitmap_lock);
                    nova_info("first_blk :%lu,nr : %lu\n",first_blk,nr);
                    nova_info("%s : add io_work :%d to conficq\n",__func__,io_work->id);
                    unsigned long f_blk, t_nr, t_bit;
                    
                    /*for test*/
                    async_pos = ino_info->aio.i_waitque.next;
                    nova_info("%s : wait queue : ",__func__);
                    while(async_pos != &ino_info->aio.i_waitque){
                         contn = container_of(async_pos, struct async_work_struct, aio_waitq);
                         nova_info("%d -->",contn->id);
                         async_pos = async_pos->next;
                    }
                    /*for test*/

                    async_pos = ino_info->aio.i_waitque.next;
                    while (async_pos != &ino_info->aio.i_waitque)
                    {
                        contn = container_of(async_pos, struct async_work_struct, aio_waitq);
                        f_blk = contn->first_blk;
                        if (f_blk + contn->blknr >= first_blk && f_blk <= first_blk + nr)
                        {
                            if(async_pos->next != &ino_info->aio.i_waitque)
                            {
                                struct async_work_struct *tmp_contn;
                                tmp_contn = container_of(async_pos->next, struct async_work_struct, aio_waitq);
                                if (tmp_contn->first_blk < first_blk + nr)
                                {
                                    async_pos = async_pos->next;
                                    list_del(&contn->aio_waitq);
                                    /*for test*/
                                    nova_info("%s , delete work: %d\n",contn->id);
                                    /*for test*/
                                    
                                    /*splice two list*/
                                    
                                    list_merge(&contn->aio_conflicq, tmp_contn->aio_conflicq.prev, &tmp_contn->aio_conflicq);
                                    tmp_contn->blknr += (tmp_contn->first_blk - contn->first_blk);
                                    tmp_contn->first_blk = contn->first_blk;
                                }
                                else
                                    break;
                            }
                            else
                                break;   
                            
                        }
                        else
                        {
                            if (f_blk > first_blk + nr)
                            {
                                contn = container_of(async_pos->prev, struct async_work_struct, aio_waitq);
                                break;
                            }
                            async_pos = async_pos->next;
                        }
                    }
                    async_pos = &contn->aio_conflicq;
                    list_add_tail(&io_work->aio_conflicq, async_pos);

                    /* for test*/
                    nova_info("%s : conficq queue : ",__func__);
                    struct async_work_struct *head = contn;
                    do{
                        nova_info("%d -->",head->id);
                        head = container_of(head->aio_conflicq.next, struct async_work_struct,aio_conflicq);
                    }while(head != contn);
                    nova_info("tail \n");
                    /* for test*/

                    t_bit = first_blk;
                    for_each_clear_bit_from(t_bit, ino_info->aio.wait_bitmap, first_blk + nr)
                        set_bit(t_bit, ino_info->aio.wait_bitmap);
                    
                    if (contn->first_blk > io_work->first_blk)
                        contn->first_blk = io_work->first_blk;

                    /*you can draw to understanding*/
                    f_blk = contn->blknr + contn->first_blk - io_work->first_blk;
                    t_nr = io_work->first_blk + io_work->blknr - contn->first_blk;
                    if (f_blk > t_nr)
                        contn->blknr = f_blk;
                    else
                        contn->blknr = t_nr;
                    spin_unlock(&ino_info->aio.wk_bitmap_lock);
                }
            }
            else
            { //00
                nova_info("%s : add io_work : %d to work\n",__func__,io_work->id);
                wkbit = first_blk;
                nova_info("first_blk :%lu,nr : %lu\n",first_blk,nr);
                spin_lock(&ino_info->aio.wk_bitmap_lock);
                for_each_clear_bit_from(wkbit, ino_info->aio.work_bitmap, first_blk + nr)
                    set_bit(wkbit, ino_info->aio.work_bitmap);
                spin_unlock(&ino_info->aio.wk_bitmap_lock);
                INIT_WORK(&(io_work->awork), nova_async_work);
                io_work->isQue = queue_work(sb->s_dio_done_wq, &(io_work->awork));
            }
        } 
        spin_unlock(&inode->i_lock); 
    }/* async*/

    return -EIOCBQUEUED;
}
