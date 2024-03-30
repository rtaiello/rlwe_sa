from math import ceil, floor, log2


class VES(object):
    def __init__(self, pt_size, add_ops, value_size, vector_size) -> None:
        super().__init__()
        self.pt_size = pt_size
        self.add_ops = add_ops
        self.value_size = value_size
        self.vector_size = vector_size
        self.element_size = value_size + ceil(log2(add_ops))
        self.compratio = floor(pt_size / self.element_size)
        self.numbatches = ceil(self.vector_size / self.compratio)
        self.encoded_size = None

    def encode(self, vs):
        bs = self.compratio
        e = []
        es = []
        for v in vs:
            e.append(v)
            bs -= 1
            if bs == 0:
                es.append(self._batch(e))
                e = []
                bs = self.compratio
        if e:
            es.append(self._batch(e))
        self.encoded_size = len(es)
        return es

    def decode(self, es):
        vs = []
        for e in es:
            for v in self._debatch(e):
                vs.append(v)
        return vs

    def _batch(self, vs):
        i = 0
        a = 0
        for v in vs:
            a |= v << self.element_size * i
            i += 1
        return a

    def _debatch(self, b):
        vs = []
        bit = 0b1
        mask = 0b1
        for _ in range(self.element_size - 1):
            mask <<= 1
            mask |= bit

        while b != 0:
            v = mask & b
            vs.append(int(v))
            b >>= self.element_size
        return vs
