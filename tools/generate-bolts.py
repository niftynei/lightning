#! /usr/bin/python3
# Script to parse spec output CSVs and produce C files.
# Released by lisa neigut under CC0:
# https://creativecommons.org/publicdomain/zero/1.0/
#
# Reads from stdin, outputs C header or body file.
#
# Standard message types:
#   msgtype,<msgname>,<value>[,<option>]
#   msgdata,<msgname>,<fieldname>,<typename>,[<count>][,<option>]
#
# TLV types:
#   tlvtype,<tlvstreamname>,<tlvname>,<value>[,<option>]
#   tlvdata,<tlvstreamname>,<tlvname>,<fieldname>,<typename>,[<count>][,<option>]
#
# Subtypes:
#   subtype,<subtypename>
#   subtypedata,<subtypename>,<fieldname>,<typename>,[<count>]

from argparse import ArgumentParser, REMAINDER
import re
import sys
import fileinput
from mako.template import Template

# Generator to give us one line at a time.
def next_line(args, lines):
    if lines is None:
        lines = fileinput.input(args)

    for i, line in enumerate(lines):
        yield i, line.strip()

# Class definitions, to keep things classy
class Field(object):
    def __init__(self, name, type_obj, optional=False):
        self.name = name
        self.type_obj = type_obj
        self.count = 1
        self.is_optional = optional
        self.is_len_field = False

    def add_count(self, count):
        self.count = int(count)

    def add_len_field(self, len_field_name):
        self.count = False
        self.len_field = len_field_name

    def is_array(self):
        return self.count > 1

    def has_len_field(self):
        return not self.count

    def is_optional(self):
        return self.is_optional

class FieldSet(object):
    def __init__(self):
        self.fields = {}
        self.optional_fields = False
        self.len_fields = {}

    def add_data_field(self, field_name, type_obj, count=1, is_optional=[]):
        if len(is_optional):
            self.optional_fields = True

        field = Field(field_name, type_obj, len(is_optional))
        if len(count):
            try:
                field.add_count(int(count))
            except ValueError:
                len_field = self.find_data_field(count)
                if not len_field:
                    raise ValueError("No length field found with name {} for {}:{}"
                                     .format(count, self.name, field_name))
                field.add_len_field(len_field.name)
                len_field.is_len_field = True
                self.len_fields[len_field.name] = len_field

        self.fields[field_name] = field

    def find_data_field(self, field_name):
        return self.fields[field_name]

    def has_optional_fields(self):
        return self.optional_fields

    def get_len_fields(self):
        return self.len_fields

class Type(FieldSet):
    def __init__(self, name):
        FieldSet.__init__(self)
        self.name = name
        self.depends_on = {}

    def add_data_field(self, field_name, type_obj, count=1, is_optional=[]):
        FieldSet.add_data_field(self, field_name, type_obj, count, is_optional)
        if type_obj.name not in self.depends_on:
            self.depends_on[type_obj.name] = type_obj

    def type_name(self):
        if self.name == 'byte':
            return 'u8'
        if self.name in ['u8', 'u16', 'u32', 'u64']:
            return self.name
        return 'struct ' + self.name

    def struct_name(self):
        return self.name

    def subtype_deps(self):
        return [ dep for dep in self.depends_on.values() if dep.is_subtype() ]

    def is_subtype(self):
        return len(self.fields) > 0

class Message(FieldSet):
    def __init__(self, name, number, option=[], enum_prefix='wire', struct_prefix=None):
        FieldSet.__init__(self)
        self.name = name
        self.number = number
        self.enum_prefix = enum_prefix
        self.option = option[0] if len(option) else None
        self.struct_prefix = struct_prefix

    def has_option(self):
        return self.option is not None

    def enum_name(self):
        return "{}_{}".format(self.enum_prefix, self.name).upper()

    def struct_name(self):
        if self.struct_prefix:
            return self.struct_prefix + "_" + self.name
        return self.name
            
class Tlv(object):
    def __init__(self, name):
        self.name = name
        self.messages = {}

    def add_message(self, tokens):
        """ tokens -> (name, value[, option]) """
        self.messages[tokens[0]] = Message(tokens[0], tokens[1], tokens[2:],
                                           self.name, self.name)

    def find_message(self, name):
        return self.messages[name]

class Master(object):
    types = {}
    tlvs = {}
    messages = {}
    inclusions = []

    def add_include(self, inclusion):
        self.inclusions.append(inclusion)

    def add_tlv(self, tlv_name):
        if tlv_name not in self.tlvs:
            self.tlvs[tlv_name] = Tlv(tlv_name)
        return self.tlvs[tlv_name]

    def add_message(self, tokens):
        """ tokens -> (name, value[, option])"""
        self.messages[tokens[0]] = Message(tokens[0], tokens[1], tokens[2:])

    def add_type(self, type_name):
        if type_name not in self.types:
            self.types[type_name] = Type(type_name)
        return self.types[type_name]

    def find_type(self, type_name):
        return self.types[type_name]

    def find_message(self, msg_name):
        return self.messages[msg_name]

    def find_tlv(self, tlv_name):
        return self.tlvs[tlv_name]

    def get_ordered_subtypes(self):
        """ We want to order subtypes such that the 'no dependency'
        types are printed first """
        subtypes = [ s for s in self.types.values() if s.is_subtype() ]

        # Start with subtypes without subtype dependencies
        sorted_types = [ s for s in subtypes if not len(s.subtype_deps()) ]
        unsorted  = [s for s in subtypes if len(s.subtype_deps())]
        while len(unsorted):
            names = [ s.name for s in sorted_types ]
            for s in list(unsorted):
                if all([dependency.name in names for dependency in s.subtype_deps() ]):
                    sorted_types.append(s)
                    unsorted.remove(s)
        return sorted_types

    def tlv_messages(self):
        return [ m for tlv in self.tlvs.values() for m in tlv.messages.values() ]

    def write(self, options, output):
        #template = Template(filename='gen/header_template')
        template = Template(filename='gen/impl_template')
        enum_sets = []
        enum_sets.append({
            'name': options.enum_name,
            'set': self.messages.values(),
        })
        for tlv in self.tlvs.values():
            enum_sets.append({
                'name': tlv.name,
                'set': tlv.messages.values(),
            })
        stuff = {}
        stuff['idem'] = re.sub(r'[^A-Z]+', '_', options.header_filename.upper())
        stuff['header_filename'] = options.header_filename
        stuff['includes'] = self.inclusions
        stuff['enum_sets'] = enum_sets
        tlvmsgs = self.tlv_messages()
        stuff['structs'] = self.get_ordered_subtypes() + self.tlv_messages()
        stuff['tlvs'] = self.tlvs.values()

        print(template.render(**stuff))


def main(options, args=None, output=sys.stdout, lines=None):
    genline = next_line(args, lines)

    # Create a new 'master' that serves as the coordinator for the file generation
    master = Master()
    try:
        while True:
            ln, line = next(genline)
            tokens = line.split(',')
            token_type = tokens[0]
            if token_type == 'subtype':
                master.add_type(tokens[1])
            elif token_type == 'subtypedata':
                subtype = master.find_type(tokens[1])
                if not subtype:
                    raise ValueError('Unknown subtype {} for data.\nat {}:{}'
                                     .format(tokens[1], ln, line))
                type_obj = master.add_type(tokens[3])
                subtype.add_data_field(tokens[2], type_obj, tokens[4])
            elif token_type == 'tlvtype':
                tlv = master.add_tlv(tokens[1])
                tlv.add_message(tokens[2:])
            elif token_type == 'tlvdata':
                type_obj = master.add_type(tokens[4])
                tlv = master.find_tlv(tokens[1])
                if not tlv:
                    raise ValueError('tlvdata for unknown tlv {}.\nat {}:{}'
                                     .format(tokens[1], ln, line))
                msg = tlv.find_message(tokens[2])
                if not msg:
                    raise ValueError('tlvdata for unknown tlv-message {}.\nat {}:{}'
                                     .format(tokens[2], ln, line))
                msg.add_data_field(tokens[3], type_obj, tokens[5])
            elif token_type == 'msgtype':
                master.add_message(tokens[1:])
            elif token_type == 'msgdata':
                message = master.find_message(tokens[1])     
                if not message:
                    raise ValueError('Unknown message type {}. {}:{}'.format(tokens[1], ln, line))
                type_obj = master.add_type(tokens[3])
                message.add_data_field(tokens[2], type_obj, tokens[4], tokens[5:])
            elif token_type.startswith('#include'):
                master.add_include(token_type)
            else:
                raise ValueError('Unknown token type {} on line {}:{}'.format(token_type, ln, line))

    except StopIteration:
        pass

    master.write(options, output)

if __name__ == "__main__":
    parser = ArgumentParser()
    parser.add_argument('header_filename', help='The filename of the header')
    parser.add_argument('enum_name', help='The name of the enum to produce')
    parser.add_argument("files", help='Files to read in (or stdin)', nargs=REMAINDER)
    parsed_args= parser.parse_args()

    main(parsed_args, parsed_args.files)
