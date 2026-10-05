"""Finite EDN data codec for the installed agent receipt; never evaluates forms."""
import json
import re

class Keyword(str):pass

def encode(value):
    if isinstance(value,Keyword):
        if not re.fullmatch(r'[A-Za-z0-9_./-]+',value):raise ValueError('invalid keyword')
        return ':'+value
    if isinstance(value,str):return json.dumps(value)
    if value is None:return 'nil'
    if value is True:return 'true'
    if value is False:return 'false'
    if isinstance(value,(int,float)):return json.dumps(value,allow_nan=False)
    if isinstance(value,list):return '['+' '.join(encode(v) for v in value)+']'
    if isinstance(value,dict):return '{'+' '.join(encode(Keyword(k))+' '+encode(v) for k,v in value.items())+'}'
    raise ValueError('unsupported EDN data')

def decode(source):
    if len(source.encode())>16*1024*1024:raise ValueError('EDN receipt too large')
    position=0
    decoder=json.JSONDecoder()
    def space():
        nonlocal position
        while position<len(source) and (source[position].isspace() or source[position]==','):position+=1
    def value(depth=0):
        nonlocal position
        if depth>64:raise ValueError('EDN nesting bound')
        space()
        if position>=len(source):raise ValueError('incomplete EDN')
        c=source[position]
        if c=='"':
            result,end=decoder.raw_decode(source,position);position=end;return result
        if c in '{[' or source.startswith('#{',position):
            is_set=source.startswith('#{',position);position+=2 if is_set else 1
            close='}' if c=='{' or is_set else ']';items=[]
            while True:
                space()
                if position>=len(source):raise ValueError('incomplete collection')
                if source[position]==close:position+=1;break
                if len(items)>100000:raise ValueError('EDN collection bound')
                items.append(value(depth+1))
            if c=='{' and not is_set:
                if len(items)%2:raise ValueError('invalid map')
                result={}
                for i in range(0,len(items),2):
                    if not isinstance(items[i],str) or items[i] in result:raise ValueError('invalid map key')
                    result[items[i]]=items[i+1]
                return result
            return items
        end=position
        while end<len(source) and not source[end].isspace() and source[end] not in ',{}[]':end+=1
        token=source[position:end];position=end
        if token=='nil':return None
        if token=='true':return True
        if token=='false':return False
        if token.startswith(':') and re.fullmatch(r':[A-Za-z0-9_./?*!+<>=-]+',token):return token[1:]
        if re.fullmatch(r'-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?',token):return json.loads(token)
        raise ValueError('unsupported EDN form')
    result=value();space()
    if position!=len(source):raise ValueError('multiple receipt forms')
    return result
