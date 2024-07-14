use std::alloc::GlobalAlloc;

use zeroize::Zeroize;

pub struct ZeroizeAllocator<T: GlobalAlloc> {
    pub inner_allocator: T,
    #[cfg(test)]
    dealloc_enabled: bool,
}

impl<T: GlobalAlloc> ZeroizeAllocator<T> {
    /// Creates a new `ZeroizeAllocator` with the given inner allocator.
    ///
    /// # Example
    /// ```
    /// use zeroize_allocator::ZeroizeAllocator;
    /// use std::alloc::System;
    /// static ALLOCATOR: zeroize_allocator::ZeroizeAllocator<std::alloc::System> =
    ///    zeroize_allocator::ZeroizeAllocator::new(std::alloc::System);
    /// ```
    ///
    pub const fn new(inner_allocator: T) -> Self {
        Self {
            inner_allocator,
            #[cfg(test)]
            dealloc_enabled: true,
        }
    }

    /// Disables deallocation of memory for testing of zeroizing behavior.
    ///
    /// # Safety
    /// This function is unsafe because it disables deallocation of memory for this allocator.
    /// This can lead to memory leaks if not used followed up with a call to `enable_dealloc` with a complete and accurate
    /// `dealloc_queue` for any memory assigned by this allocator that was dropped while between a call to this method and `enable_dealloc`.
    #[cfg(test)]
    unsafe fn disable_dealloc(&mut self) {
        self.dealloc_enabled = false;
    }

    /// Enables deallocation of memory after testing zeroizing behavior.
    /// The optional `dealloc_queue` parameter allows for the deallocation of memory that was not deallocated previously due to deallocation being disabled.
    ///
    /// # Safety
    /// This function is unsafe because undefined behavior can result if the caller does not ensure all of the following:
    /// ptr must denote a block of memory currently allocated via this allocator,
    /// layout must be the same layout that was used to allocate that block of memory.

    #[cfg(test)]
    unsafe fn enable_dealloc(
        &mut self,
        mut dealloc_queue: Option<Vec<(*mut u8, std::alloc::Layout)>>,
    ) {
        self.dealloc_enabled = true;
        if let Some(ref mut dealloc_queue) = dealloc_queue {
            for (ptr, layout) in dealloc_queue.drain(..) {
                self.inner_allocator.dealloc(ptr, layout);
            }
        }
    }

    #[cfg(test)]
    unsafe fn test_dealloc(&self, ptr: *mut u8, layout: std::alloc::Layout) {
        if self.dealloc_enabled {
            self.inner_allocator.dealloc(ptr, layout);
        }
    }
}

unsafe impl<T: GlobalAlloc> GlobalAlloc for ZeroizeAllocator<T> {
    unsafe fn alloc(&self, layout: std::alloc::Layout) -> *mut u8 {
        self.inner_allocator.alloc(layout)
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: std::alloc::Layout) {
        // zeroize memory before deallocating
        let slice = std::slice::from_raw_parts_mut(ptr, layout.size());
        slice.zeroize();

        // deallocate memory
        #[cfg(test)]
        self.test_dealloc(ptr, layout);
        #[cfg(not(test))]
        self.inner_allocator.dealloc(ptr, layout);
    }
}

#[cfg(test)]
mod tests {
    use std::{alloc::Layout, vec};

    use super::*;

    #[test]
    fn zeroize_string() {
        const STRING_SLICE: &str = "to zeroize";

        let mut allocator = ZeroizeAllocator::new(std::alloc::System);
        unsafe {
            // Do not really dealloc memory, just zeroize it
            allocator.disable_dealloc();
        }

        let donor = String::from(STRING_SLICE);
        let layout = Layout::for_value(&donor);
        let ptr = unsafe { allocator.alloc(layout) };
        let capacity = donor.capacity();

        // Fill the memory location with the string
        unsafe {
            std::ptr::copy_nonoverlapping(STRING_SLICE.as_ptr(), ptr, STRING_SLICE.len());
        }

        // Assert that the memory location of the string is correct
        unsafe {
            assert_eq!(
                std::slice::from_raw_parts(ptr, capacity),
                format!("{}", STRING_SLICE).as_bytes()
            );
        }

        // Zeroize the memory location
        unsafe {
            allocator.dealloc(ptr, layout);
        }

        // Memory has been zeroized
        unsafe {
            assert_eq!(
                std::slice::from_raw_parts(ptr, capacity),
                &[0; STRING_SLICE.len()] // format!("{}\0", STRING_SLICE).as_bytes()
            );
        }

        // Finally deallocate the memory
        unsafe {
            allocator.enable_dealloc(Some(vec![(
                ptr,
                Layout::from_size_align_unchecked(capacity, 1),
            )]));
        }
    }

    #[test]
    fn zeroize_vec_2() {
        const VEC: &[u8] = &[1, 2, 3, 4, 5];
        let mut allocator = ZeroizeAllocator::new(std::alloc::System);
        unsafe {
            // Do not really dealloc memory, just zeroize it
            allocator.disable_dealloc();
        }

        let v = Vec::from(VEC);
        let layout = Layout::for_value(&v);
        let ptr = unsafe { allocator.alloc(layout) };
        let capacity = v.capacity();

        // Fill the memory location with the vector
        unsafe {
            std::ptr::copy_nonoverlapping(VEC.as_ptr(), ptr, VEC.len());
        }

        // Assert that the memory location of the vector is correct
        unsafe {
            assert_eq!(std::slice::from_raw_parts(ptr, capacity), VEC);
        }

        // Zeroize the memory location
        unsafe {
            allocator.dealloc(ptr as *mut u8, layout);
        }

        // Memory has been zeroized
        unsafe {
            assert_eq!(std::slice::from_raw_parts(ptr, capacity), &[0; VEC.len()]);
        }

        // Finally deallocate the memory
        unsafe {
            allocator.enable_dealloc(Some(vec![(
                ptr as *mut u8,
                Layout::from_size_align_unchecked(capacity, 1),
            )]));
        }
    }
}
