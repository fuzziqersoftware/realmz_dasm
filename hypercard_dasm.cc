#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <exception>
#include <phosg/Encoding.hh>
#include <phosg/Filesystem.hh>
#include <phosg/Strings.hh>
#include <stdexcept>
#include <string>
#include <vector>

#include "ResourceFile.hh"

using namespace std;



Image get_manhole_card_pict(const string& part_text) {
  static unordered_map<int16_t, Image> picts_cache;
  if (picts_cache.empty()) {
    for (const string& item : list_directory("files/the_manhole.picts.out")) {
      if (!ends_with(item, ".bmp")) {
        continue;
      }
      size_t pict_offset = item.find("_PICT_");
      int16_t pict_id = strtol(item.c_str() + pict_offset + 6, nullptr, 10);
      string filename = "files/the_manhole.picts.out/" + item;
      fprintf(stderr, "[manhole_picts_cache] loading PICT %hd from %s\n",
          pict_id, filename.c_str());
      picts_cache.emplace(pict_id, filename.c_str());
    }
  }

  int16_t pict_id = stol(part_text, nullptr, 10);
  try {
    fprintf(stderr, "[manhole_picts_cache] part_text = \"%s\", pict_id = %hd\n",
        part_text.c_str(), pict_id);
    return picts_cache.at(pict_id);
  } catch (const out_of_range&) {
    fprintf(stderr, "[manhole_picts_cache] part_text = \"%s\", pict_id = %hd not found\n",
        part_text.c_str(), pict_id);
    return Image(512, 342);
  }
}



void print_extra_data(StringReader& r, size_t end_offset, const char* what) {
  size_t offset = r.where();
  if (offset > end_offset) {
    throw runtime_error(string_printf("%s parsing extended beyond end", what));
  } else if (offset < end_offset) {
    string extra_data = r.read(end_offset - offset);
    if (extra_data.find_first_not_of('\0') != string::npos) {
      fprintf(stderr, "warning: extra data after %s ignored:\n", what);
      print_data(stderr, extra_data, offset);
    }
  }
}

string get_cstr_pad(StringReader& r) {
  bool initial_parity = r.where() & 1;
  string ret = r.get_cstr();
  if (initial_parity != (r.where() & 1)) {
    r.get_u8();
  }
  return ret;
}

string trim_and_decode(const string& src) {
  size_t zero_pos = src.find('\0');
  string ret = (zero_pos != string::npos) ? src.substr(0, zero_pos) : src;
  return decode_mac_roman(ret);
}

string autoformat_hypertalk(const string& src) {
  vector<string> lines = split(src, '\n');
  size_t indent = 0;
  bool prev_is_if_then = false;
  for (size_t line_num = 0; line_num < lines.size(); line_num++) {
    string& line = lines[line_num];

    // strip whitespace from the beginning and end; we'll auto-indent later
    size_t line_start_offset = line.find_first_not_of(" \t");
    size_t line_end_offset = line.find_last_not_of(" \t");
    if (line_start_offset == string::npos) {
      line.clear();
    } else {
      line = line.substr(line_start_offset, line_end_offset - line_start_offset + 1);

      // lowercase the line for pseudo-parsing
      string lowercase_line = line;
      transform(lowercase_line.begin(), lowercase_line.end(), lowercase_line.begin(), tolower);
      size_t comment_start = lowercase_line.find("--");
      if (comment_start != string::npos) {
        lowercase_line.resize(comment_start);
        size_t lowercase_line_end_offset = lowercase_line.find_last_not_of(" \t");
        if (lowercase_line_end_offset == string::npos) {
          lowercase_line.clear();
        } else {
          lowercase_line.resize(lowercase_line_end_offset + 1);
        }
      }

      bool is_else = starts_with(lowercase_line, "else"); // true if the line is an 'else' or 'else if' statement
      bool is_if = is_else ? starts_with(lowercase_line, "else if ") : starts_with(lowercase_line, "if "); // true if the line is an 'if' or 'else if' statement
      bool is_else_then = is_else && !is_if && !ends_with(lowercase_line, "else"); // true if the line is an 'else' statement with an inline body
      bool is_if_then = is_if && !ends_with(lowercase_line, " then"); // true if the line is an 'if' or 'else if' statement with an inline body
      bool is_end = starts_with(lowercase_line, "end "); // true if the line is an 'end' statement
      bool is_repeat = starts_with(lowercase_line, "repeat"); // true if the line is a 'repeat' statement
      bool is_on = starts_with(lowercase_line, "on "); // true if the line is an 'on' statement

      bool should_unindent_here = is_end || (is_else && !prev_is_if_then);
      bool should_indent_after = (is_if && !is_if_then) || (is_else && !is_else_then && !is_if_then) || is_repeat || is_on;

      if (should_unindent_here) {
        if (indent >= 2) {
          indent -= 2;
        } else {
          fprintf(stderr, "warning: autoformatting attempted to unindent past zero on line %zu\n",
              line_num + 1);
        }
      }
      line.insert(0, indent, ' ');
      if (should_indent_after) {
        indent += 2;
      }

      prev_is_if_then = is_if_then;
    }
  }
  return join(lines, "\n");
}



struct BlockHeader {
  uint32_t size;
  uint32_t type;
  int32_t id;

  void byteswap() {
    this->size = bswap32(this->size);
    this->type = bswap32(this->type);
    this->id = bswap32(this->id);
  }
} __attribute__((packed));

struct StackBlock {
  BlockHeader header; // type 'STAK'
  uint32_t card_count;
  int32_t card_id; // perhaps last used card?
  int32_t list_block_id;
  uint16_t user_level; // 1-5
  // 0x8000 = can't modify
  // 0x4000 = can't delete
  // 0x2000 = private access
  // 0x0800 = can't abort
  // 0x0400 = can't peek
  uint16_t flags;
  uint32_t hypercard_versions[4];
  uint16_t card_height;
  uint16_t card_width;
  uint64_t patterns[0x28];
  string script;

  StackBlock(StringReader& r) {
    // Format:
    //   BlockHeader header; // type 'STAK'
    //   uint8_t unknown1[0x20]; // 0x0C
    //   uint32_t card_count; // 0x2C
    //   int32_t card_id; // 0x30; perhaps last used card?
    //   int32_t list_block_id; // 0x34
    //   uint8_t unknown2[0x10]; // 0x38
    //   uint16_t user_level; // 0x48; value is 1-5
    //   uint16_t unknown3; // 0x4A
    //   uint16_t flags; // 0x4C
    //   uint8_t unknown4[0x12]; // 0x4E
    //   uint32_t hypercard_versions[4]; // 0x60
    //   uint8_t unknown5[0x148]; // 0x70
    //   uint16_t card_height; // 0x1B8
    //   uint16_t card_width; // 0x1BA
    //   uint8_t unknown6[0x104]; // 0x1BC
    //   uint64_t patterns[0x28]; // 0x2C0
    //   uint8_t unknown7[0x200]; // 0x400
    //   char script[0]; // 0x600
    this->header = r.get_sw<BlockHeader>(false);
    this->card_count = r.pget_u32r(r.where() + 0x2C);
    this->card_id = r.pget_u32r(r.where() + 0x30);
    this->list_block_id = r.pget_u32r(r.where() + 0x34);
    this->user_level = r.pget_u16r(r.where() + 0x48);
    this->flags = r.pget_u16r(r.where() + 0x4C);
    for (size_t x = 0; x < 4; x++) {
      this->hypercard_versions[x] = r.pget_u32r(r.where() + 0x60 + (x * 4));
    }
    this->card_height = r.pget_u16r(r.where() + 0x1B8);
    this->card_width = r.pget_u16r(r.where() + 0x1BA);
    for (size_t x = 0; x < 0x28; x++) {
      this->patterns[x] = r.pget_u16r(r.where() + 0x2C0 + (x * 8));
    }
    this->script = trim_and_decode(r.preadx(r.where() + 0x600, this->header.size - 0x600));

    r.go(r.where() + this->header.size);
  }
};

struct StyleTableBlock {
  BlockHeader header; // type 'STBL'
  uint32_t style_count;

  struct Entry {
    int16_t font_id; // -1 = inherited from field styles
    uint16_t style_flags; // bold, italic, underline, etc. may be 0xFFFF for inherit
    int16_t font_size; // -1 = inherit

    Entry(StringReader& r) {
      // Format:
      //   uint8_t unknown1[0x10];
      //   int16_t font_id;
      //   uint16_t style_flags;
      //   int16_t font_size;
      //   uint16_t unknown2;
      r.skip(0x10);
      this->font_id = r.get_s16r();
      this->style_flags = r.get_u16r();
      this->font_size = r.get_s16r();
      r.skip(2);
    }
  };

  vector<Entry> entries;

  StyleTableBlock(StringReader& r) {
    // Format:
    //   BlockHeader header; // type 'STBL'
    //   uint32_t unknown1;
    //   uint32_t style_count;
    this->header = r.get_sw<BlockHeader>();
    r.skip(4);
    this->style_count = r.get_u32r();

    while (this->entries.size() < this->style_count) {
      this->entries.emplace_back(r);
    }
  }
};

struct FontTableBlock {
  BlockHeader header; // type 'FTBL'
  unordered_map<int16_t, string> font_id_to_name;

  FontTableBlock(StringReader& r) {
    // Format:
    //   BlockHeader header; // type 'FTBL'
    //   uint8_t unknown1[6];
    //   uint16_t font_count;
    //   uint32_t unknown2;
    //   For each entry:
    //     int16_t font_id;
    //     uint8_t name_length;
    //     char name[name_length];
    //     char pad; // only if name_length is even
    this->header = r.get_sw<BlockHeader>();
    r.skip(6);
    uint16_t font_count = r.get_u16r();
    r.skip(4);
    for (size_t x = 0; x < font_count; x++) {
      int16_t font_id = r.get_s16r();
      uint8_t name_length = r.get_u8();
      string name = r.read(name_length);
      if (!(name_length & 1)) {
        r.get_u8(); // end of entry is always word-aligned
      }
      this->font_id_to_name.emplace(font_id, name);
    }
  }
};

struct PageTableListBlock {
  BlockHeader header; // type 'LIST'
  uint16_t card_blocks_size;
  vector<int32_t> page_block_ids;

  PageTableListBlock(StringReader& r) {
    // Format:
    //   BlockHeader header; // type 'LIST'
    //   uint32_t page_table_count;
    //   uint8_t unknown1[8];
    //   uint16_t card_blocks_size;
    //   uint8_t unknown2[0x10];
    //   For each entry:
    //     uint16_t unknown1;
    //     int32_t page_block_id;
    this->header = r.get_sw<BlockHeader>();
    uint32_t page_table_count = r.get_u32r();
    r.skip(8);
    this->card_blocks_size = r.get_u16r();
    r.skip(0x20);
    for (size_t x = 0; x < page_table_count; x++) {
      r.skip(2);
      this->page_block_ids.emplace_back(r.get_s32r());
    }
  }
};

struct PageTableBlock {
  BlockHeader header; // type 'PAGE'
  uint8_t unknown1[0x0C];

  struct Entry {
    int32_t card_id;
    uint8_t card_flags; // 0x20 = marked
    uint8_t extra[0]; // size determined by PageTableListBlock::card_blocks_size
  } __attribute__((packed));
} __attribute__((packed));

struct CardOrBackgroundBlock {
  struct PartEntry {
    uint16_t entry_size;
    int16_t part_id;
    uint8_t type; // 1 = button, 2 = field
    // 0x80 = hidden
    // 0x20 = don't wrap
    // 0x10 = don't search
    // 0x08 = shared text
    // 0x04 = fixed line height
    // 0x02 = auto tab
    // 0x01 = disable / lock text
    uint8_t low_flags;
    int16_t rect_top;
    int16_t rect_left;
    int16_t rect_bottom;
    int16_t rect_right;
    // 0x8000 = show name / auto select
    // 0x4000 = highlight / show lines
    // 0x2000 = wide margins / auto highlight
    // 0x1000 = shared highlight / multiple lines
    // 0x0F00 masks the button family number
    // 0x000F sets style
    //   buttons: 0 = transparent, 1 = opaque, 2 = rectangle, 3 = roundrect, 4 = shadow, 5 = checkbox, 6 = radio, 8 = standard, 9 = default, 10 = oval, 11 = popup
    //   fields: 0 = transparent, 1 = opaque, 2 = rectangle, 4 = shadow, 7 = scrolling
    uint16_t high_flags;
    union {
      uint16_t title_width;
      uint16_t last_selected_line;
    };
    union {
      int16_t icon_id;
      uint16_t first_selected_line;
    };
    uint16_t text_alignment; // 0 = left/default, 1 = center, -1 = right, -2 = force left align?
    int16_t font_id;
    uint16_t font_size;
    // 0x8000 = group
    // 0x4000 = extend
    // 0x2000 = condense
    // 0x1000 = shadow
    // 0x0800 = outline
    // 0x0400 = underline
    // 0x0200 = italic
    // 0x0100 = bold
    uint16_t style_flags;
    uint16_t line_height;
    string name; // c-string
    string script; // c-string
    // Format ends with a padding byte if needed to make the size even

    PartEntry(StringReader& r) {
      size_t start_offset = r.where();
      // Format exactly matches the struct above
      this->entry_size = r.get_u16r();
      this->part_id = r.get_s16r();
      this->type = r.get_u8();
      this->low_flags = r.get_u8();
      this->rect_top = r.get_s16r();
      this->rect_left = r.get_s16r();
      this->rect_bottom = r.get_s16r();
      this->rect_right = r.get_s16r();
      this->high_flags = r.get_u16r();
      this->title_width = r.get_u16r(); // also sets last_selected_line
      this->icon_id = r.get_s16r(); // also sets first_selected_line
      this->text_alignment = r.get_u16r();
      this->font_id = r.get_s16r();
      this->font_size = r.get_u16r();
      this->style_flags = r.get_u16r();
      this->line_height = r.get_u16r();
      this->name = r.get_cstr();
      if (r.get_u8() != 0) {
        throw runtime_error("part does not have double zero between name and script");
      }
      this->script = trim_and_decode(r.get_cstr());
      print_extra_data(r, start_offset + this->entry_size, "part entry");
    }
  };

  struct PartContentEntry {
    int16_t part_id; // if negative, card part; if positive, background part
    map<uint16_t, uint16_t> offset_to_style_entry_index;
    string text;

    PartContentEntry(StringReader& r) {
      // Format if styles_size & 0x8000:
      //   int16_t part_id;
      //   uint16_t entry_size;
      //   uint16_t styles_size;
      //   For each style (styles_length / 4 of them):
      //     uint16_t start_offset;
      //     uint16_t style_entry_index;
      //   char text[...];
      // Format if !(styles_size & 0x8000):
      //   int16_t part_id;
      //   uint16_t entry_size;
      //   uint8_t zero;
      //   char text[...];
      size_t start_offset = r.where();
      this->part_id = r.get_s16r();
      uint16_t entry_size = r.get_u16r();

      uint16_t styles_size;
      uint8_t has_styles = r.get_u8();
      if (has_styles & 0x80) {
        styles_size = (has_styles << 8) | r.get_u8();
      } else {
        styles_size = 0;
      }

      if (styles_size != 0) {
        // from hypercard.org:
        // if >= 0x8000, there is (styles_size - 32770) bytes of style data prepended to the text, otherwise the text is mono-styled
        throw runtime_error("unimplemented: styles_size != 0");
      }
      // TODO: styles parsing would look something like this:
      // for (size_t x = 0; x < styles_size / 4; x++) {
      //   uint16_t start_offset = r.get_u16r();
      //   uint16_t style_entry_index = r.get_u16r();
      //   this->offset_to_style_entry_index.emplace(start_offset, style_entry_index);
      // }
      ssize_t text_length = entry_size - 1; // TODO: this will have to change when style parsing works
      if (text_length < 0) {
        throw runtime_error("entry_size inconsistent with header + styles length");
      }
      // Note: we intentionally do not use get_cstr_pad here, since the string
      // may start on an unaligned boundary.
      this->text = r.read(text_length);
    }
  };

  struct OSAScriptData {
    // Format:
    //   uint16_t script_offset; // relative to location of script_size
    //   uint16_t script_size;
    //   uint8_t extra_header_data[...]; // if script_offset != 2 presumably
    //   char script[script_size];
    string extra_header_data;
    string script;

    OSAScriptData() = default;
    OSAScriptData(StringReader& r) {
      uint16_t script_offset = r.get_u16r();
      uint16_t script_size = r.get_u16r();
      if (script_offset < 2) {
        throw runtime_error("OSA script overlaps size field");
      }
      if (script_offset > 2) {
        this->extra_header_data = r.read(script_offset - 2);
      }
      this->script = r.read(script_size);
    }
  };

  BlockHeader header; // type 'CARD' or 'BKGD'
  int32_t bmap_block_id; // 0 = transparent
  // 0x4000 = can't delete
  // 0x2000 = hide card picture
  // 0x0800 = don't search
  uint16_t flags;
  int32_t background_id;
  uint32_t script_type; // 0 = HyperTalk, 'WOSA' = compiled OSA language like AppleScript
  vector<PartEntry> parts;
  vector<PartContentEntry> part_contents;
  string name;
  string script;
  OSAScriptData osa_script_data;

  CardOrBackgroundBlock(StringReader& r) {
    // Format:
    //   BlockHeader header; // type 'CARD' or 'BKGD'
    //   uint32_t unknown1;
    //   int32_t bmap_block_id; // 0 = transparent
    //   uint16_t flags;
    //   uint8_t unknown2[0x0E];
    //   int32_t background_id; // this field is not present for BKGD blocks
    //   uint16_t parts_count;
    //   uint8_t unknown3[6];
    //   uint16_t parts_contents_count;
    //   uint32_t script_type; // 0 = HyperTalk, 'WOSA' = compiled OSA language like AppleScript
    //   PartEntry parts[parts_count];
    //   PartContentEntry part_contents[part_contents_count];
    //   char name[...]; (c-string)
    //   char script[...]; (c-string)
    //   OSAScriptData osa_script_data; (if script_type is WOSA)
    size_t start_offset = r.where();
    this->header = r.get_sw<BlockHeader>();
    r.skip(4);
    this->bmap_block_id = r.get_s32r();
    this->flags = r.get_u16r();
    r.skip(0x0E);
    if (this->header.type == 0x43415244) {
      this->background_id = r.get_s32r();
    } else {
      this->background_id = 0;
    }
    uint16_t parts_count = r.get_u16r();
    r.skip(6);
    uint16_t parts_contents_count = r.get_u16r();
    this->script_type = r.get_u32r();
    for (size_t x = 0; x < parts_count; x++) {
      this->parts.emplace_back(r);
    }
    for (size_t x = 0; x < parts_contents_count; x++) {
      // Note: it looks like these must always start on aligned boundaries, but
      // they don't necessarily end on aligned boundaries!
      if (r.where() & 1) {
        if (r.get_u8() != 0) {
          throw runtime_error(string_printf("part content entry alignment byte at %zX is not zero", r.where() - 1));
        }
      }
      this->part_contents.emplace_back(r);
    }
    if (r.where() & 1) {
      if (r.get_u8() != 0) {
        throw runtime_error(string_printf("alignment byte at %zX after part content entries is not zero", r.where()));
      }
    }
    this->name = r.get_cstr();
    // If the script is blank, it looks like the CARD block sometimes just ends
    // early, so we have to check the offset here.
    if (r.where() < start_offset + this->header.size - 1) {
      this->script = trim_and_decode(r.get_cstr());
    }
    if (this->script_type == 0x574F5341) { // 'WOSA'
      this->osa_script_data = OSAScriptData(r);
    }
  }
};



int main(int argc, char* argv[]) {
  printf("fuzziqer software hypercard stack disassembler\n\n");

  string filename;
  string out_dir;
  for (int x = 1; x < argc; x++) {
    if (filename.empty()) {
      filename = argv[x];
    } else if (out_dir.empty()) {
      out_dir = argv[x];
    } else {
      fprintf(stderr, "excess argument: %s\n", argv[x]);
    }
  }

  if (filename.empty()) {
    fprintf(stderr, "no input filename given\n");
    return 0;
  }
  if (out_dir.empty()) {
    out_dir = string_printf("%s.out", filename.c_str());
  }
  mkdir(out_dir.c_str(), 0777);

  string data = load_file(filename);
  StringReader r(data.data(), data.size());
  size_t card_w = 0;
  size_t card_h = 0;
  while (!r.eof()) {
    size_t block_offset = r.where();
    BlockHeader header = r.get_sw<BlockHeader>(false);
    size_t block_end = block_offset + header.size;

    switch (header.type) {
      case 0x5354414B: { // STAK
        string disassembly_filename = out_dir + "/stack.txt";
        StackBlock stack(r);
        auto f = fopen_unique(disassembly_filename, "wt");
        fprintf(f.get(), "-- stack: %s\n", filename.c_str());
        fprintf(f.get(), "-- card count: %u\n", stack.card_count);
        fprintf(f.get(), "-- list block id: %08X\n", stack.list_block_id);
        fprintf(f.get(), "-- user level: %hu\n", stack.user_level);
        fprintf(f.get(), "-- flags: %04hX\n", stack.flags);
        fprintf(f.get(), "-- dimensions: %hux%hu\n\n", stack.card_width, stack.card_height);
        card_w = stack.card_width;
        card_h = stack.card_height;
        fprintf(f.get(), "----- script -----\n\n");
        string formatted_script = autoformat_hypertalk(stack.script);
        fwritex(f.get(), formatted_script);
        fprintf(stderr, "... %s\n", disassembly_filename.c_str());
        break;
      }
      case 0x424B4744: // BKGD
      case 0x43415244: { // CARD
        bool is_card = header.type == 0x43415244;
        CardOrBackgroundBlock card(r);
        string layout_img_filename = string_printf("%s/%s_%d_layout.bmp",
            out_dir.c_str(), is_card ? "card" : "background", card.header.id);
        string disassembly_filename = string_printf("%s/%s_%d.txt",
            out_dir.c_str(), is_card ? "card" : "background", card.header.id);

        Image layout_img(card_w, card_h);
        uint8_t pxcol; // draw white lines/text if over image, black if over white
        if (card_w == 512 && card_h == 342 && card.part_contents.size() == 1) {
          layout_img = get_manhole_card_pict(card.part_contents[0].text);
          pxcol = 0xFF;
        } else {
          layout_img.fill_rect(0, 0, card_w, card_h, 0xFF, 0xFF, 0xFF);
          pxcol = 0x00;
        }
        auto f = fopen_unique(disassembly_filename, "wt");
        fprintf(f.get(), "-- card: %d from stack: %s\n", card.header.id, filename.c_str());
        fprintf(f.get(), "-- bmap block id: %d\n", card.bmap_block_id);
        fprintf(f.get(), "-- flags: %04hX\n", card.flags);
        fprintf(f.get(), "-- background id: %d\n", card.background_id);
        bool is_hypertalk = (card.script_type == 0 || card.script_type == 10);
        fprintf(f.get(), "-- script type: %d (%s)\n", card.script_type,
            is_hypertalk ? "HyperTalk" : ((card.script_type == 0x574F5341) ? "OSA" : "unknown"));
        fprintf(f.get(), "-- card name: %s\n", card.name.c_str());
        if (is_hypertalk) {
          fprintf(f.get(), "----- script -----\n\n");
          string formatted_script = autoformat_hypertalk(card.script);
          fwritex(f.get(), formatted_script);
        }

        for (const auto& part : card.parts) {
          layout_img.draw_horizontal_line(part.rect_left, part.rect_right, part.rect_top, 0, pxcol, pxcol, pxcol);
          layout_img.draw_horizontal_line(part.rect_left, part.rect_right, part.rect_bottom, 0, pxcol, pxcol, pxcol);
          layout_img.draw_vertical_line(part.rect_left, part.rect_top, part.rect_bottom, 0, pxcol, pxcol, pxcol);
          layout_img.draw_vertical_line(part.rect_right, part.rect_top, part.rect_bottom, 0, pxcol, pxcol, pxcol);
          layout_img.draw_text(part.rect_left + 1, part.rect_top + 1, nullptr, nullptr, pxcol, pxcol, pxcol, 0xFF, 0x00, 0x00, 0x00, 0x00, "%hd", part.part_id);
          fprintf(f.get(), "\n\n");
          if (part.type == 0 || part.type > 2) {
            fprintf(f.get(), "-- part %hd (type %hhu)\n", part.part_id, part.type);
          } else {
            fprintf(f.get(), "-- part %hd (%s)\n", part.part_id, (part.type == 1) ? "button" : "field");
          }
          fprintf(f.get(), "-- low flags: %02hhX\n", part.low_flags);
          fprintf(f.get(), "-- high flags: %04hX\n", part.high_flags);
          fprintf(f.get(), "-- rect: left=%hd top=%hd right=%hd bottom=%hd\n",
              part.rect_left, part.rect_top, part.rect_bottom, part.rect_right);
          fprintf(f.get(), "-- title width / last selected line: %hu\n", part.title_width);
          fprintf(f.get(), "-- icon id / first selected line: %hd / %hu\n", part.icon_id, part.first_selected_line);
          fprintf(f.get(), "-- text alignment: %hu\n", part.text_alignment);
          fprintf(f.get(), "-- font id: %hd\n", part.font_id);
          fprintf(f.get(), "-- text size: %hu\n", part.font_size);
          fprintf(f.get(), "-- style flags: %hu\n", part.style_flags);
          fprintf(f.get(), "-- line height: %hu\n", part.line_height);
          fprintf(f.get(), "-- part name: %s\n", part.name.c_str());
          fprintf(f.get(), "----- script -----\n\n");
          string formatted_script = autoformat_hypertalk(part.script);
          fwritex(f.get(), formatted_script);
        }

        for (const auto& part_contents : card.part_contents) {
          fprintf(f.get(), "\n\n");
          fprintf(f.get(), "-- part contents for part %hd\n", part_contents.part_id);
          if (!part_contents.offset_to_style_entry_index.empty()) {
            fprintf(f.get(), "-- note: style data is present\n");
          }
          fprintf(f.get(), "----- text -----\n");
          fwritex(f.get(), part_contents.text);
        }

        // TODO: do something with OSA script data
        layout_img.save(layout_img_filename, Image::ImageFormat::WindowsBitmap);
        fprintf(stderr, "... %s\n", disassembly_filename.c_str());
        fprintf(stderr, "... %s\n", layout_img_filename.c_str());
        break;
      }
      default: {
        uint32_t type_swapped = bswap32(header.type);
        fprintf(stderr, "warning: skipping unknown block at %08zX size: %08X type: %08X (%.4s) id: %08X (%d)\n",
            r.where(), header.size, type_swapped, reinterpret_cast<const char*>(&type_swapped), header.id, header.id);

        if (header.size < sizeof(BlockHeader)) {
          throw runtime_error("block is smaller than header");
        }
        r.go(block_end);
      }
    }

    print_extra_data(r, block_end, "block");
  }

  return 0;
}
