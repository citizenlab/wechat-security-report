"""
Decodes and interpret JSON output from decrypt-keylog.py.

Expects JSON data line-by-line to stdin.
Outputs JSON data.
"""

import sys

import blackboxprotobuf
import zlib
import hexdump
import json

from urllib.parse import unquote

def url_decode(s):
    decoded = unquote(s)
    while decoded != s:
        s = decoded
        decoded = unquote(s)
    return decoded

# code for json parsing taken largely from blackboxprotobuf repo. 
# changes noted below in comments.
def bytes_to_string(obj):
    return url_decode(obj.decode('utf8', 'backslashreplace'))

    
def _get_json_writeable_obj(in_obj, out_obj, bytes_as_hex=False):
    """Converts non-string values (like bytes) to strings
    in lists/dictionaries recursively.
    """
    if isinstance(in_obj, list):
        for item in in_obj:
            if isinstance(item, list):
                i = []
                out_obj.append(i)
                _get_json_writeable_obj(item, i, bytes_as_hex)
            elif isinstance(item, dict):
                i = {}
                out_obj.append(i)
                _get_json_writeable_obj(item, i, bytes_as_hex)
            elif isinstance(item, bytes) or isinstance(item, bytearray): # added bytearray here
                if bytes_as_hex:
                    out_obj.append(item.hex())
                else:
                    out_obj.append(bytes_to_string(item))
            else:
                # added: check if json decodable?
                if str(item).startswith("{") and str(item).endswith("}"):
                    try:
                        item = json.loads(item)
                        if isinstance(item, list):
                            i = []
                            out_obj.append(i)
                            _get_json_writeable_obj(item, i, bytes_as_hex)
                        elif isinstance(item, dict):
                            i = {}
                            out_obj.append(i)
                            _get_json_writeable_obj(item, i, bytes_as_hex)
                        continue
                    except:
                        pass
                # added: URL decode
                out_obj.append(url_decode(str(item)))
    else: #dict
        for k, v in in_obj.items():
            if isinstance(v, list):
                i = []
                out_obj[k] = i
                _get_json_writeable_obj(v, i, bytes_as_hex)
            elif isinstance(v, dict):
                i = {}
                out_obj[k] = i
                _get_json_writeable_obj(v, i, bytes_as_hex)
            elif isinstance(v, bytes) or isinstance(v, bytearray): # added bytearray here
                if bytes_as_hex:
                    out_obj[k] = v.hex()
                else:
                    out_obj[k] = bytes_to_string(v)
            else:
                  # added: check if json decodable?
                if str(v).startswith("{") and str(v).endswith("}"):
                    try:
                        v = json.loads(v)
                        if isinstance(v, list):
                            i = []
                            out_obj[k] = i
                            _get_json_writeable_obj(v, i, bytes_as_hex)
                        elif isinstance(v, dict):
                            i = {}
                            out_obj[k] = i
                            _get_json_writeable_obj(v, i, bytes_as_hex)
                        continue
                    except:
                        pass
                out_obj[k] = url_decode(str(v))

def protobuf_to_dict(buf, message_type=None, bytes_as_hex=False):
    """Encode to python dictionary and dump to JSON.
    """
    value, message_type = blackboxprotobuf.decode_message(buf, message_type)
    value_cleaned = {}
    _get_json_writeable_obj(value, value_cleaned, bytes_as_hex)
    return value_cleaned, message_type


def extract_hex(lines, start_idx):
    end_idx = start_idx
    while END_FLAG not in lines[end_idx]:
        end_idx += 1
    hexdata = "".join(lines[start_idx:end_idx]).strip()
    if end_idx - start_idx > 1 or "  " in lines[start_idx]:
        hexdata = " ".join(
            [lines[i][10:-18].strip() for i in range(start_idx, end_idx)]
        ).strip()
    if hexdata.startswith("78"): #zlib compressed
        return zlib.decompress(bytearray.fromhex(hexdata)), end_idx
    return bytearray.fromhex(hexdata), end_idx

def extract_metadata(metadata):
    md = {
      "sent": metadata[0] == 0x00
    }
    if not md["sent"]:
        return md
    md["len"] = int.from_bytes(metadata[:4], "big")
    url_len = int.from_bytes(metadata[4:6], "big")
    end = 6+url_len
    md["url"] = metadata[6:end].decode()
    host_len = int.from_bytes(metadata[end:end+2], "big")
    md["host"] = metadata[end+2:end+2+host_len].decode()
    end = end + 2 + host_len

    return md
    
def main():
    for line in sys.stdin: 
        line = json.loads(line)
        metadata = bytearray.fromhex(line["metadata"])
        plaintext_bytes = bytearray.fromhex(line["plaintext"])
        data = extract_metadata(metadata)

        # Print relevant data from plaintext 
        if plaintext_bytes[0] == 0x78:
            plaintext_bytes = zlib.decompress(plaintext_bytes)
        try: 
            message, typedef = protobuf_to_dict(plaintext_bytes)
            data["protobuf"] = message
        except Exception as e:
            data["error"] = repr(e)
            raise e
        print(json.dumps(data))


if __name__ == "__main__":
    main()
