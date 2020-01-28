from ctypes import c_void_p, c_char_p, CDLL, byref, Structure
from pathlib import Path
import re


class DL_info(Structure):
    _fields_ = [
        ('dli_fname', c_char_p),
        ('dli_fbase', c_void_p),
        ('dli_sname', c_char_p),
        ('dli_saddr', c_void_p)
    ]

c = CDLL(None)
dladdr = c.dladdr
dyld_get_image_name = c._dyld_get_image_name
dyld_get_image_name.restype = c_char_p
dyld_get_image_header = c._dyld_get_image_header
dyld_get_image_header.restype = c_void_p
dyld_get_image_vmaddr_slide = c._dyld_get_image_vmaddr_slide
dyld_get_image_vmaddr_slide.restype = c_void_p

def get_image_headers_info():
    image_headers_data = {}
    for i in range(c._dyld_image_count()):
        name = dyld_get_image_name(i).split(b'/')[-1].decode()
        pointer_to_header = dyld_get_image_header(i)
        slide = dyld_get_image_vmaddr_slide(i)
        image_headers_data[name] = {'pointer': pointer_to_header, 'slide': slide}
    return image_headers_data


class Symbolicator:
    def __init__(self, file_path):
        self._file_path = Path(file_path)
        self._source_text = self._file_path.read_text()
        self._symbolicate_table = []
        self._symbolicated_text = None
        self._address_info_dict = {}
        self._image_headers_info = {}
        
    def _load_images(self, lines):
        for line in lines:
            *_, image_path = line.split()
            CDLL(image_path)
        self._image_headers_info = get_image_headers_info()
        
    def _get_addr_info(self, lines):
        setdefault = self._address_info_dict.setdefault
        images_data = self._image_headers_info
        for l in lines:
            if l=='\n': break
            _, name, _, base_addr, _, offset = l.split()
            setdefault(name, [base_addr, images_data[name]['pointer'], set()])[2].add(int(offset))
           
    def _parse_logs(self):
        sections= self._source_text.split('\n\n')
        get_info = self._get_addr_info
        for s in sections[::-1]:
            if not s: continue
            line, *lines = s.splitlines()
            if not lines: continue
            if line == 'Binary Images:':
                self._load_images(lines)
            elif re.match('Thread [0-9]+(| Crashed):', line):
                get_info(lines)
            elif re.match('Thread [0-9]+ name:', lines[0]):
                get_info(lines[1:])
    
    def _make_symbolicate_table(self):
        self._parse_logs()
        symbolicate_table = self._symbolicate_table
        for old_base_addr, base_addr, offsets in self._address_info_dict.values():
            for offset in offsets:
                info = DL_info()
                if not dladdr(c_void_p(base_addr+offset), byref(info)):
                    continue
                name = info.dli_sname
                addr = info.dli_saddr
                if not addr: continue
                symbolicate_table.append((f'{old_base_addr} + {offset}', f'{name.decode()} + {base_addr+offset-addr}'))
        
    def symbolicate(self):
        if self._symbolicated_text:
            return self._symbolicated_text
        self._make_symbolicate_table()
        symbolicated_text = self._source_text
        for table in self._symbolicate_table:
            symbolicated_text = symbolicated_text.replace(*table)
        self._symbolicated_text = symbolicated_text
        return symbolicated_text
        
        
if __name__ == '__main__':
    file_path = next(Path('.').glob('*.ips*'))
    s = Symbolicator(file_path)
    print(file_path)
    t = s.symbolicate()
    with open('symbolicated.txt', 'w') as f:
        f.write(t)
