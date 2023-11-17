const CAPATCITY: usize = 10000;

#[derive(Clone, Copy)]
pub struct Queue<T: Sized + Copy + Clone + Default> {
    head: usize,
    tail: usize,
    data: [T; CAPATCITY],
}

impl<T> Queue<T>
where
    T: Sized + Copy + Clone + Default,
{
    #[inline(always)]
    pub fn new() -> Self {
        Queue {
            head: 0,
            tail: 0,
            data: [Default::default(); CAPATCITY],
        }
    }

    #[inline(always)]
    fn increase(i: usize) -> usize {
        (i + 1) % CAPATCITY
    }

    #[inline(always)]
    pub fn push(&mut self, item: T) {
        self.data[self.tail] = item;
        self.tail = Self::increase(self.tail);
    }

    pub fn pop(&mut self) -> T {
        let item = self.data[self.head];
        self.head = Self::increase(self.head);
        item
    }
}
