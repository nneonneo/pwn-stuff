''' Build an evil pickle with simple syntax.

Useful especially if you want to do more than just eval(...) '''
from __future__ import print_function

import sys
import imp
import pickle

class F(object):
    ''' Wrap a built-in or imported function '''
    def __init__(self, f):
        self.f = f
        self.args = None
    def __call__(self, *args):
        if self.args is not None:
            # called again, create new wrapper
            return F(self)(*args)
        self.args = args
        return self
    def __getattr__(self, key):
        return F(getattr)(self, key)
    def __reduce__(self):
        assert self.args is not None, "F instance must be called!"
        return (self.f, self.args)
for meth in ['__getitem__', '__setitem__', '__delitem__', '__add__', '__mul__', '__divmod__']:
    setattr(F, meth, (lambda meth: lambda self, *args: F(getattr)(self, meth)(*args))(meth))

class DummyModuleLoader:
    dummy_modules = []
    want_load = None

    @classmethod
    def remove_all(cls):
        for m in cls.dummy_modules:
            del sys.modules[m]
        del cls.dummy_modules[:]
        cls.want_load = None

    @classmethod
    def find_module(cls, fullname, path=None):
        if fullname == cls.want_load or cls.is_package(fullname):
            cls.dummy_modules.append(fullname)
            return cls

    @classmethod
    def is_package(cls, fullname):
        if cls.want_load is None:
            return False
        want = cls.want_load.split('.')
        have = fullname.split('.')
        if want[:len(have)] == have:
            return True
        return False

    @classmethod
    def load_module(cls, fullname):
        ispkg = cls.is_package(fullname)
        mod = sys.modules.setdefault(fullname, imp.new_module(fullname))
        mod.__file__ = "dummy"
        mod.__loader__ = cls
        if ispkg:
            mod.__path__ = []
            mod.__package__ = fullname
        else:
            mod.__package__ = fullname.rpartition('.')[0]
        return mod
sys.meta_path.append(DummyModuleLoader)

def M(m, f):
    ''' Wrap a module function.

    Call as M('module.submodule', 'method')
    '''

    if m not in sys.modules:
        DummyModuleLoader.want_load = m
        __import__(m)

    if not hasattr(sys.modules[m], f):
        def dummy_function(*args):
            print("%s.%s(%s) called" % (m, f, ', '.join(map(str, args))))
        dummy_function.__module__ = m
        dummy_function.__name__ = f
        dummy_function.__qualname__ = f
        setattr(sys.modules[m], f, dummy_function)

    return F(getattr(sys.modules[m], f))

def test(obj):
    p = pickle.dumps(obj)
    DummyModuleLoader.remove_all()
    return pickle.loads(p)

if __name__ == '__main__':
    # Simple example with eval
    print(test(F(eval)("3+3")))

    # More complicated example with subprocess
    print(test(M('subprocess', 'Popen')(['ls', '-la'], 0, None, None, -1).communicate()[0]))

    # Really complicated example with images, multiple references, and statements
    img = M('PIL.Image', 'new')('RGB', (640, 480))
    img2 = M('PIL.Image', 'new')('RGB', (200, 240), '#ff7700')
    print(test((img.paste(img2, (30, 30)), img.save('/tmp/foo.jpg'))))
