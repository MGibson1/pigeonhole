mod buf_reader;
mod error;
mod file;
mod zeroize_allocator;

#[global_allocator]
static ALLOCATOR: zeroize_allocator::ZeroizeAllocator<std::alloc::System> =
    zeroize_allocator::ZeroizeAllocator::new(std::alloc::System);
