
import json
import setting
bn128=setting.getBn128()
lib=bn128
FQ, FQ2, FQ12, field_modulus = lib.FQ, lib.FQ2, lib.FQ12, lib.field_modulus
pairing,G1, G2, G12, b, b2, b12, is_inf, is_on_curve, eq, add, double, curve_order, multiply = \
      lib.pairing,lib.G1, lib.G2, lib.G12, lib.b, lib.b2, lib.b12, lib.is_inf, lib.is_on_curve, lib.eq, lib.add, lib.double, lib.curve_order, lib.multiply
import py_ecc

def G1ToList(p1):
    print(type(p1))
    b:List=[]
    for i in p1:
        b.append(int(i))
    return b

def G2ToList(p2):
    a:List=[]
    for i in p2:
        a.extend(list(i.coeffs))
    return a

class ElementEncoder(json.JSONEncoder):
    def default(self, obj):
        # print(type(obj),obj)
        if isinstance(obj, py_ecc.fields.optimized_bn128_FQ2) or isinstance(obj, py_ecc.fields.bn128_FQ2):
            return list(obj.coeffs)
        elif isinstance(obj, py_ecc.fields.optimized_bn128_FQ) or isinstance(obj, py_ecc.fields.bn128_FQ):
            return int(obj)
        elif isinstance(obj, py_ecc.fields.optimized_bn128_FQ12) or isinstance(obj, py_ecc.fields.bn128_FQ12):
            return list(obj.coeffs)
        elif str(type(obj)).find("FQP_corresponding_FQ_class")>0:# isinstance(obj, py_ecc.fields.field_elements.FQP_corresponding_FQ_class):
            return int(str(obj))
        else:
            return super(ElementEncoder, self).default(obj)

# class ElementDecoder(json.JSONDecoder):
#     def __init__(self, *args, **kwargs):
#         json.JSONDecoder.__init__(self, object_hook=self.object_hook, *args, **kwargs)

#     def object_hook(self, obj, ):
#         if '_type' not in obj:
#             return obj
#         type = obj['_type']
#         if type == 'bytes':
#             return bytes(obj['value'], encoding = "utf-8")
#         if type == 'element':
#             return group.deserialize(obj['value'])
#         return obj

def dumps(data,c=ElementEncoder):
    return json.dumps(data,cls=c)

# def loads(data,c= ElementDecoder):
#     return json.loads(data,cls=c)
if __name__ == "__main__":
    print(type(G1))
    print(dumps(G1))
    print(dumps(G2))
