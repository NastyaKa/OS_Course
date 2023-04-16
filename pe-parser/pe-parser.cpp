#include <bitset>
#include <cstring>
#include <fstream>
#include <iostream>

#define uchar unsigned char
#define uint unsigned int

struct sections {
  uint virtual_size;
  uint rva;
  uint raw;
  sections() : virtual_size(0), rva(0), raw(0) {}
  sections(uint virtual_size_, uint rva_, uint raw_)
      : virtual_size(virtual_size_), rva(rva_), raw(raw_) {}
};

uint convert_to_dec(uchar *buf, size_t from, size_t to) {
  uint res = 0;
  for (size_t i = to; i > from; i--) {
    res *= 256;
    res += buf[i - 1];
  }
  return res;
}

uint get_from_addr(std::ifstream &file, uint addr, size_t sz) {
  file.seekg(addr, file.beg);
  uchar pe_sign[sz];
  file.read((char *)pe_sign, sz);
  return convert_to_dec(pe_sign, 0, sz);
}

bool check_signature(std::ifstream &file, uint &pe_signature_start) {
  file.seekg(pe_signature_start, file.beg);
  uchar pe_buf[4];
  file.read((char *)pe_buf, 4);
  static char pe_signature[4] = {'P', 'E', '\0', '\0'};
  for (size_t i = 0; i < 4; i++) {
    if (pe_signature[i] != pe_buf[i]) {
      return false;
    }
  }
  return true;
}

uint get_raw(struct sections *section, uint &cur_rva, uint sz) {
  for (uint i = 0; i < sz; i++) {
    if (section[i].rva <= cur_rva &&
        cur_rva <= section[i].rva + section[i].virtual_size) {
      return section[i].raw + cur_rva - section[i].rva;
    }
  }
  return 0;
}

uint print_name(std::ifstream &file, uint cur_raw) {
  uchar buf[32];
  bool f_end = false;
  uint cnt = 0;
  for (uint i = 0; !f_end; i++) {
    file.seekg(cur_raw + i * 32, file.beg);
    file.read((char *)buf, 32);
    for (uint j = 0; j < 32; j++) {
      cnt++;
      if (buf[j] == '\0') {
        f_end = true;
        break;
      }
      std::cout << buf[j];
    }
  }
  std::cout << '\n';
  return cnt;
}

void fill_sections_t(std::ifstream &file, struct sections *sections_list,
                     uint &optional_header_beg, uint &number_of_sections) {

  uint section_header_beg = optional_header_beg + 0xf0;
  uint section_header_end = section_header_beg + 40 * number_of_sections;
  for (uint i = section_header_beg, j = 0; i < section_header_end;
       i += 40, j++) {
    sections_list[j] = sections(get_from_addr(file, i + 0x8, 4), // virtual_size
                                get_from_addr(file, i + 0xC, 4), // rva
                                get_from_addr(file, i + 0x14, 4)); // raw
  }
}

uint is_pe(std::ifstream &file, uint &signature_beg) {
  if (check_signature(file, signature_beg)) {
    std::cout << "PE\n";
    return 0;
  }
  std::cout << "Not PE\n";
  return 1;
}

void import_functions(std::ifstream &file, struct sections *sections_list,
                      uint number_of_sections, uint &optional_header_beg) {
  uint import_t_rva = get_from_addr(file, optional_header_beg + 0x78, 4);
  uint import_raw = get_raw(sections_list, import_t_rva, number_of_sections);

  uchar import_t[20];
  for (uint i = import_raw;; i += 20) {
    file.seekg(i, file.beg);
    file.read((char *)import_t, 20);

    bool emp = true;
    for (uint j = 0; j < 20; j++) {
      if (import_t[j] != '\0') {
        emp = false;
        break;
      }
    }
    if (emp) {
      break;
    }

    uint import_rva = convert_to_dec(import_t, 12, 16);
    uint import_t_raw = get_raw(sections_list, import_rva, number_of_sections);

    print_name(file, import_t_raw);

    uint lookup_t_rva = convert_to_dec(import_t, 0, 4);
    uint lookup_t_raw =
        get_raw(sections_list, lookup_t_rva, number_of_sections);

    for (int j = lookup_t_raw;; j += 8) {
      uint ord_num = get_from_addr(file, j, 4);
      uint name_t_rva = get_from_addr(file, j + 4, 4);
      if (ord_num == 0 && name_t_rva == 0) {
        break;
      } else if (name_t_rva & 0x80000000) {
        continue;
      }
      uint name_t_raw = get_raw(sections_list, ord_num, number_of_sections);
      std::cout << "    ";
      print_name(file, name_t_raw + 2);
    }
  }
}

void export_functions(std::ifstream &file, struct sections *sections_list,
                      uint number_of_sections, uint &optional_header_beg) {
  uint export_t_rva = get_from_addr(file, optional_header_beg + 0x70, 4);
  uint export_t_raw = get_raw(sections_list, export_t_rva, number_of_sections);

  uint num_of_name_pointers = get_from_addr(file, export_t_raw + 0x18, 4);

  uint name_pointer_rva = get_from_addr(file, export_t_raw + 0x20, 4);
  uint name_pointer_raw =
      get_raw(sections_list, name_pointer_rva, number_of_sections);

  uint export_name_rva = get_from_addr(file, name_pointer_raw, 4);
  uint export_name_raw =
      get_raw(sections_list, export_name_rva, number_of_sections);
  uint prev = 0;
  for (uint i = 0; i < num_of_name_pointers; i++) {
    prev += print_name(file, export_name_raw + prev);
  }
}

int main(int argc, char *argv[]) {
  if (argc < 3) {
    std::cout << "Error. Too few arguments\n";
    return 0;
  }

  std::ifstream pe_file;
  pe_file.open(argv[2]);
  if (!pe_file.is_open()) {
    std::cout << argv[2] << '\n';
    std::cout << "Error. Can't open this file\n";
    return 0;
  }

  uint pe_signature_beg = get_from_addr(pe_file, 0x3C, 4);

  if (strcmp(argv[1], "is-pe") == 0) {
    uint res = is_pe(pe_file, pe_signature_beg);
    pe_file.close();
    return res;
  }

  uint coff_beg = pe_signature_beg + 4;
  uint optional_header_beg = coff_beg + 20;
  uint number_of_sections = get_from_addr(pe_file, coff_beg + 2, 2);
  struct sections sections_list[number_of_sections];

  fill_sections_t(pe_file, sections_list, optional_header_beg,
                  number_of_sections);

  if (strcmp(argv[1], "import-functions") == 0) {
    import_functions(pe_file, sections_list, number_of_sections,
                     optional_header_beg);
  } else if (strcmp(argv[1], "export-functions") == 0) {
    export_functions(pe_file, sections_list, number_of_sections,
                     optional_header_beg);
  } else {
    std::cout << "Unknown command\n";
    pe_file.close();
    return 2;
  }
  pe_file.close();
  return 0;
}
