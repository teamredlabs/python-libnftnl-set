#include <Python.h>
#include <structmember.h>

#include <linux/netfilter.h>
#include <linux/netfilter/nf_tables.h>

#include <libmnl/libmnl.h>
#include <libnftnl/set.h>

// BEGIN: _nf_nftnl_attr_spec

enum {
    NF_NFTNL_ATTR_IO_READ = 0x01,
    NF_NFTNL_ATTR_IO_WRITE = 0x02,
};

enum {
    NF_NFTNL_ATTR_TYPE_RAW,
    NF_NFTNL_ATTR_TYPE_STR,
    NF_NFTNL_ATTR_TYPE_U32,
    NF_NFTNL_ATTR_TYPE_U64,
};

typedef struct {
    char* attr_name;
    uint16_t attr_code;
    uint16_t attr_type;
    uint8_t attr_io;
} _nf_nftnl_attr_spec;

static PyObject* _nf_nftnl_attr_spec_dict_new (_nf_nftnl_attr_spec attrs[]) {
    PyObject* attr_key;
    PyObject* attr_value;
    PyObject* attr_value_code;
    PyObject* attr_value_type;
    PyObject* attr_value_io;
    PyObject* attr_dict;
    int i;

    attr_dict = PyDict_New();
    if (attr_dict != NULL) {
        for (i = 0; attrs[i].attr_name != NULL; i++) {
            attr_key = PyString_FromString(attrs[i].attr_name);

            attr_value_code = PyInt_FromLong((long) attrs[i].attr_code);
            attr_value_type = PyInt_FromLong((long) attrs[i].attr_type);
            attr_value_io = PyInt_FromLong((long) attrs[i].attr_io);
            attr_value = PyTuple_Pack(3, attr_value_code, attr_value_type, attr_value_io);
            Py_DECREF(attr_value_type);
            Py_DECREF(attr_value_code);
            Py_DECREF(attr_value_io);

            PyDict_SetItem(attr_dict, attr_key, attr_value);

            Py_DECREF(attr_value);
            Py_DECREF(attr_key);
        }
    }

    return attr_dict;
}

static uint8_t _nf_nftnl_attr_spec_dict_get (PyObject* attr_dict, PyObject* attr_name,
                                             uint16_t* attr_code, uint16_t* attr_type,
                                             uint8_t* attr_io) {
    PyObject* attr_value = NULL;
    if (attr_dict && PyDict_Contains(attr_dict, attr_name)) {
        attr_value = PyDict_GetItem(attr_dict, attr_name);
        if (attr_value) {
            *attr_code = (uint16_t) PyInt_AsLong(PyTuple_GetItem(attr_value, 0));
            *attr_type = (uint16_t) PyInt_AsLong(PyTuple_GetItem(attr_value, 1));
            *attr_io = (uint8_t) PyInt_AsLong(PyTuple_GetItem(attr_value, 2));
            return 1;
        }
    }
    return 0;
}

// END: _nf_nftnl_attr_spec

// BEGIN: NetfilterElementHandle

typedef struct {
    PyObject_HEAD
    struct nftnl_set* owner;
    struct nftnl_set_elem* handle;
} NetfilterElementHandle;

static PyObject* NetfilterElementHandle_new (PyTypeObject* type, PyTupleObject* args) {
    NetfilterElementHandle* self;
    self = (NetfilterElementHandle*) type->tp_alloc(type, 0);
    self->owner = NULL;
    self->handle = NULL;
    return (PyObject*) self;
}

static int NetfilterElementHandle_init (NetfilterElementHandle* self, PyTupleObject* args) {
    return 0;
}

static void NetfilterElementHandle_dealloc (NetfilterElementHandle* self) {
    if (!self->owner) nftnl_set_elem_free(self->handle);
    Py_TYPE(self)->tp_free((PyObject*) self);
}

static PyObject* NetfilterElementHandleAttributesDict = NULL;

static PyObject* _NetfilterElementHandle_GetAttr_raw (NetfilterElementHandle* self, uint16_t attr) {
    const char* raw; uint32_t rawlen;
    raw = (const char*) nftnl_set_elem_get(self->handle, attr, &rawlen);
    return PyString_FromStringAndSize(raw, (Py_ssize_t) rawlen);
}

static PyObject* _NetfilterElementHandle_GetAttr_str (NetfilterElementHandle* self, uint16_t attr) {
    return PyString_FromString(nftnl_set_elem_get_str(self->handle, attr));
}

static PyObject* _NetfilterElementHandle_GetAttr_u32 (NetfilterElementHandle* self, uint16_t attr) {
    return PyInt_FromLong((long) nftnl_set_elem_get_u32(self->handle, attr));
}

static PyObject* _NetfilterElementHandle_GetAttr_u64 (NetfilterElementHandle* self, uint16_t attr) {
    return PyInt_FromLong((long) nftnl_set_elem_get_u64(self->handle, attr));
}

static PyObject* NetfilterElementHandle_GetAttr (NetfilterElementHandle* self, PyObject* name) {
    PyObject* dict = NetfilterElementHandleAttributesDict;
    uint16_t attr_code; uint16_t attr_type; uint8_t attr_io;
    if (_nf_nftnl_attr_spec_dict_get(dict, name, &attr_code, &attr_type, &attr_io)) {
        if (attr_io & NF_NFTNL_ATTR_IO_READ) {
            switch (attr_type) {
                case NF_NFTNL_ATTR_TYPE_RAW:
                    return _NetfilterElementHandle_GetAttr_raw(self, attr_code);
                case NF_NFTNL_ATTR_TYPE_STR:
                    return _NetfilterElementHandle_GetAttr_str(self, attr_code);
                case NF_NFTNL_ATTR_TYPE_U32:
                    return _NetfilterElementHandle_GetAttr_u32(self, attr_code);
                case NF_NFTNL_ATTR_TYPE_U64:
                    return _NetfilterElementHandle_GetAttr_u64(self, attr_code);
            }
        }
        PyErr_SetString(PyExc_OSError, "Cannot perform read on attribute");
        return NULL;
    }
    return PyObject_GenericGetAttr((PyObject*) self, name);
}

static int _NetfilterElementHandle_SetAttr_raw (NetfilterElementHandle* self, PyObject* value, uint16_t attr) {
    char* raw; uint32_t rawlen;
    if (!PyString_Check(value)) {
        PyErr_SetString(PyExc_OSError, "Attribute must be bytes");
        return -1;
    }
    raw = PyString_AS_STRING(value);
    rawlen = PyString_GET_SIZE(value);
    nftnl_set_elem_set(self->handle, attr, (const void*) raw, rawlen);
    return 0;
}

static int _NetfilterElementHandle_SetAttr_str (NetfilterElementHandle* self, PyObject* value, uint16_t attr) {
    char* str;
    if (!(str = PyString_AsString(value))) {
        PyErr_SetString(PyExc_OSError, "Attribute must be a string");
        return -1;
    }
    nftnl_set_elem_set_str(self->handle, attr, str);
    return 0;
}

static int _NetfilterElementHandle_SetAttr_u32 (NetfilterElementHandle* self, PyObject* value, uint16_t attr) {
    uint32_t u32;
    if (!PyInt_Check(value)) {
        PyErr_SetString(PyExc_OSError, "Attribute must be a uint32_t");
        return -1;
    }
    u32 = (uint32_t) PyInt_AS_LONG(value);
    nftnl_set_elem_set_u32(self->handle, attr, u32);
    return 0;
}

static int _NetfilterElementHandle_SetAttr_u64 (NetfilterElementHandle* self, PyObject* value, uint16_t attr) {
    uint64_t u64;
    if (!PyInt_Check(value)) {
        PyErr_SetString(PyExc_OSError, "Attribute must be a uint64_t");
        return -1;
    }
    u64 = (uint64_t) PyInt_AS_LONG(value);
    nftnl_set_elem_set_u64(self->handle, attr, u64);
    return 0;
}

static int NetfilterElementHandle_SetAttr (NetfilterElementHandle* self, PyObject* name, PyObject* value) {
    PyObject* dict = NetfilterElementHandleAttributesDict;
    uint16_t attr_code; uint16_t attr_type; uint8_t attr_io;
    if (_nf_nftnl_attr_spec_dict_get(dict, name, &attr_code, &attr_type, &attr_io)) {
        if (attr_io & NF_NFTNL_ATTR_IO_WRITE) {
            switch (attr_type) {
                case NF_NFTNL_ATTR_TYPE_RAW:
                    return _NetfilterElementHandle_SetAttr_raw(self, value, attr_code);
                case NF_NFTNL_ATTR_TYPE_STR:
                    return _NetfilterElementHandle_SetAttr_str(self, value, attr_code);
                case NF_NFTNL_ATTR_TYPE_U32:
                    return _NetfilterElementHandle_SetAttr_u32(self, value, attr_code);
                case NF_NFTNL_ATTR_TYPE_U64:
                    return _NetfilterElementHandle_SetAttr_u64(self, value, attr_code);
            }
        }
        PyErr_SetString(PyExc_OSError, "Cannot perform write on attribute");
        return -1;
    }
    return PyObject_GenericSetAttr((PyObject*) self, name, value);
}

static _nf_nftnl_attr_spec NetfilterElementHandleAttributes [] = {
    {"flags", NFTNL_SET_ELEM_FLAGS, NF_NFTNL_ATTR_TYPE_U32, NF_NFTNL_ATTR_IO_READ | NF_NFTNL_ATTR_IO_WRITE},
    {"key", NFTNL_SET_ELEM_KEY, NF_NFTNL_ATTR_TYPE_RAW, NF_NFTNL_ATTR_IO_READ | NF_NFTNL_ATTR_IO_WRITE},
    {"verdict", NFTNL_SET_ELEM_VERDICT, NF_NFTNL_ATTR_TYPE_U32, NF_NFTNL_ATTR_IO_READ | NF_NFTNL_ATTR_IO_WRITE},
    {"chain", NFTNL_SET_ELEM_CHAIN, NF_NFTNL_ATTR_TYPE_STR, NF_NFTNL_ATTR_IO_READ | NF_NFTNL_ATTR_IO_WRITE},
    {"data", NFTNL_SET_ELEM_DATA, NF_NFTNL_ATTR_TYPE_RAW, NF_NFTNL_ATTR_IO_READ | NF_NFTNL_ATTR_IO_WRITE},
    {"timeout", NFTNL_SET_ELEM_TIMEOUT, NF_NFTNL_ATTR_TYPE_U64, NF_NFTNL_ATTR_IO_READ | NF_NFTNL_ATTR_IO_WRITE},
    {"userdata", NFTNL_SET_ELEM_USERDATA, NF_NFTNL_ATTR_TYPE_RAW, NF_NFTNL_ATTR_IO_READ | NF_NFTNL_ATTR_IO_WRITE},
    {"objref", NFTNL_SET_ELEM_OBJREF, NF_NFTNL_ATTR_TYPE_STR, NF_NFTNL_ATTR_IO_READ | NF_NFTNL_ATTR_IO_WRITE},
    {"expiration", NFTNL_SET_ELEM_EXPIRATION, NF_NFTNL_ATTR_TYPE_U64, NF_NFTNL_ATTR_IO_READ},
    {NULL}
};

static PyMemberDef NetfilterElementHandle_members[] = {
    {NULL}
};

static PyMethodDef NetfilterElementHandle_methods[] = {
    {NULL}
};

static PyTypeObject NetfilterElementHandleType = {
    PyVarObject_HEAD_INIT(NULL, 0)
    "libnftnlset.NetfilterElementHandle",          /* tp_name */
    sizeof(NetfilterElementHandle),                /* tp_basicsize */
    0,                                             /* tp_itemsize */
    (destructor) NetfilterElementHandle_dealloc,   /* tp_dealloc */
    0,                                             /* tp_print */
    0,                                             /* tp_getattr */
    0,                                             /* tp_setattr */
    0,                                             /* tp_compare */
    0,                                             /* tp_repr */
    0,                                             /* tp_as_number */
    0,                                             /* tp_as_sequence */
    0,                                             /* tp_as_mapping */
    0,                                             /* tp_hash */
    0,                                             /* tp_call */
    0,                                             /* tp_str */
    (getattrofunc) NetfilterElementHandle_GetAttr, /* tp_getattro */
    (setattrofunc) NetfilterElementHandle_SetAttr, /* tp_setattro */
    0,                                             /* tp_as_buffer */
    Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE,      /* tp_flags */
    "Wrapper for (struct nftnl_set_elem *)",       /* tp_doc */
    0,                                             /* tp_traverse */
    0,                                             /* tp_clear */
    0,                                             /* tp_richcompare */
    0,                                             /* tp_weaklistoffset */
    0,                                             /* tp_iter */
    0,                                             /* tp_iternext */
    NetfilterElementHandle_methods,                /* tp_methods */
    NetfilterElementHandle_members,                /* tp_members */
    0,                                             /* tp_getset */
    0,                                             /* tp_base */
    0,                                             /* tp_dict */
    0,                                             /* tp_descr_get */
    0,                                             /* tp_descr_set */
    0,                                             /* tp_dictoffset */
    (initproc) NetfilterElementHandle_init,        /* tp_init */
    0,                                             /* tp_alloc */
    (newfunc) NetfilterElementHandle_new,          /* tp_new */
};

// END: NetfilterElementHandle

// BEGIN: NetfilterSetHandle

typedef struct {
    PyObject_HEAD
    struct nftnl_set* handle;
} NetfilterSetHandle;

static PyObject* NetfilterSetHandle_new (PyTypeObject* type, PyTupleObject* args) {
    NetfilterSetHandle* self;
    self = (NetfilterSetHandle*) type->tp_alloc(type, 0);
    self->handle = NULL;
    return (PyObject*) self;
}

static int NetfilterSetHandle_init (NetfilterSetHandle* self, PyTupleObject* args) {
    return 0;
}

static void NetfilterSetHandle_dealloc (NetfilterSetHandle* self) {
    nftnl_set_free(self->handle);
    Py_TYPE(self)->tp_free((PyObject*) self);
}

static PyObject* NetfilterSetHandleAttributesDict = NULL;

static PyObject* NetfilterSetHandle_add (NetfilterSetHandle* self, PyTupleObject* args) {
    PyObject* object; NetfilterElementHandle* element;

    if (!PyArg_ParseTuple((PyObject*) args, "O", &object)) {
        PyErr_SetString(PyExc_ValueError, "Parameters must be (NetfilterElementHandle element)");
        return NULL;
    }

    if (!PyObject_IsInstance((PyObject*) object, (PyObject*) &NetfilterElementHandleType)) {
        PyErr_SetString(PyExc_ValueError, "Parameters must be (NetfilterElementHandle element)");
        return NULL;
    }

    element = (NetfilterElementHandle*) object;

    if (element->owner) {
        PyErr_SetString(PyExc_ValueError, "Element already belongs to another set");
        return NULL;
    }

    nftnl_set_elem_add(self->handle, element->handle);
    element->owner = self->handle;

    Py_RETURN_NONE;
}

static PyObject* _NetfilterSetHandle_GetAttr_raw (NetfilterSetHandle* self, uint16_t attr) {
    const char* raw; uint32_t rawlen;
    raw = (const char*) nftnl_set_get_data(self->handle, attr, &rawlen);
    return PyString_FromStringAndSize(raw, (Py_ssize_t) rawlen);
}

static PyObject* _NetfilterSetHandle_GetAttr_str (NetfilterSetHandle* self, uint16_t attr) {
    return PyString_FromString(nftnl_set_get_str(self->handle, attr));
}

static PyObject* _NetfilterSetHandle_GetAttr_u32 (NetfilterSetHandle* self, uint16_t attr) {
    return PyInt_FromLong((long) nftnl_set_get_u32(self->handle, attr));
}

static PyObject* _NetfilterSetHandle_GetAttr_u64 (NetfilterSetHandle* self, uint16_t attr) {
    return PyInt_FromLong((long) nftnl_set_get_u64(self->handle, attr));
}

static PyObject* NetfilterSetHandle_GetAttr (NetfilterSetHandle* self, PyObject* name) {
    PyObject* dict = NetfilterSetHandleAttributesDict;
    uint16_t attr_code; uint16_t attr_type; uint8_t attr_io;
    if (_nf_nftnl_attr_spec_dict_get(dict, name, &attr_code, &attr_type, &attr_io)) {
        if (attr_io & NF_NFTNL_ATTR_IO_READ) {
            switch (attr_type) {
                case NF_NFTNL_ATTR_TYPE_RAW:
                    return _NetfilterSetHandle_GetAttr_raw(self, attr_code);
                case NF_NFTNL_ATTR_TYPE_STR:
                    return _NetfilterSetHandle_GetAttr_str(self, attr_code);
                case NF_NFTNL_ATTR_TYPE_U32:
                    return _NetfilterSetHandle_GetAttr_u32(self, attr_code);
                case NF_NFTNL_ATTR_TYPE_U64:
                    return _NetfilterSetHandle_GetAttr_u64(self, attr_code);
            }
        }
        PyErr_SetString(PyExc_OSError, "Cannot perform read on attribute");
        return NULL;
    }
    return PyObject_GenericGetAttr((PyObject*) self, name);
}

static int _NetfilterSetHandle_SetAttr_raw (NetfilterSetHandle* self, PyObject* value, uint16_t attr) {
    char* raw; uint32_t rawlen;
    if (!PyString_Check(value)) {
        PyErr_SetString(PyExc_OSError, "Attribute must be bytes");
        return -1;
    }
    raw = PyString_AS_STRING(value);
    rawlen = PyString_GET_SIZE(value);
    nftnl_set_set_data(self->handle, attr, (const void*) raw, rawlen);
    return 0;
}

static int _NetfilterSetHandle_SetAttr_str (NetfilterSetHandle* self, PyObject* value, uint16_t attr) {
    char* str;
    if (!(str = PyString_AsString(value))) {
        PyErr_SetString(PyExc_OSError, "Attribute must be a string");
        return -1;
    }
    nftnl_set_set_str(self->handle, attr, str);
    return 0;
}

static int _NetfilterSetHandle_SetAttr_u32 (NetfilterSetHandle* self, PyObject* value, uint16_t attr) {
    uint32_t u32;
    if (!PyInt_Check(value)) {
        PyErr_SetString(PyExc_OSError, "Attribute must be a uint32_t");
        return -1;
    }
    u32 = (uint32_t) PyInt_AS_LONG(value);
    nftnl_set_set_u32(self->handle, attr, u32);
    return 0;
}

static int _NetfilterSetHandle_SetAttr_u64 (NetfilterSetHandle* self, PyObject* value, uint16_t attr) {
    uint64_t u64;
    if (!PyInt_Check(value)) {
        PyErr_SetString(PyExc_OSError, "Attribute must be a uint64_t");
        return -1;
    }
    u64 = (uint64_t) PyInt_AS_LONG(value);
    nftnl_set_set_u64(self->handle, attr, u64);
    return 0;
}

static int NetfilterSetHandle_SetAttr (NetfilterSetHandle* self, PyObject* name, PyObject* value) {
    PyObject* dict = NetfilterSetHandleAttributesDict;
    uint16_t attr_code; uint16_t attr_type; uint8_t attr_io;
    if (_nf_nftnl_attr_spec_dict_get(dict, name, &attr_code, &attr_type, &attr_io)) {
        if (attr_io & NF_NFTNL_ATTR_IO_WRITE) {
            switch (attr_type) {
                case NF_NFTNL_ATTR_TYPE_RAW:
                    return _NetfilterSetHandle_SetAttr_raw(self, value, attr_code);
                case NF_NFTNL_ATTR_TYPE_STR:
                    return _NetfilterSetHandle_SetAttr_str(self, value, attr_code);
                case NF_NFTNL_ATTR_TYPE_U32:
                    return _NetfilterSetHandle_SetAttr_u32(self, value, attr_code);
                case NF_NFTNL_ATTR_TYPE_U64:
                    return _NetfilterSetHandle_SetAttr_u64(self, value, attr_code);
            }
        }
        PyErr_SetString(PyExc_OSError, "Cannot perform write on attribute");
        return -1;
    }
    return PyObject_GenericSetAttr((PyObject*) self, name, value);
}

static _nf_nftnl_attr_spec NetfilterSetHandleAttributes [] = {
    {"table", NFTNL_SET_TABLE, NF_NFTNL_ATTR_TYPE_STR, NF_NFTNL_ATTR_IO_READ | NF_NFTNL_ATTR_IO_WRITE},
    {"name", NFTNL_SET_NAME, NF_NFTNL_ATTR_TYPE_STR, NF_NFTNL_ATTR_IO_READ | NF_NFTNL_ATTR_IO_WRITE},
    {"flags", NFTNL_SET_FLAGS, NF_NFTNL_ATTR_TYPE_U32, NF_NFTNL_ATTR_IO_READ | NF_NFTNL_ATTR_IO_WRITE},
    {"key_type", NFTNL_SET_KEY_TYPE, NF_NFTNL_ATTR_TYPE_U32, NF_NFTNL_ATTR_IO_READ | NF_NFTNL_ATTR_IO_WRITE},
    {"key_len", NFTNL_SET_KEY_LEN, NF_NFTNL_ATTR_TYPE_U32, NF_NFTNL_ATTR_IO_READ | NF_NFTNL_ATTR_IO_WRITE},
    {"data_type", NFTNL_SET_DATA_TYPE, NF_NFTNL_ATTR_TYPE_U32, NF_NFTNL_ATTR_IO_READ | NF_NFTNL_ATTR_IO_WRITE},
    {"data_len", NFTNL_SET_DATA_LEN, NF_NFTNL_ATTR_TYPE_U32, NF_NFTNL_ATTR_IO_READ | NF_NFTNL_ATTR_IO_WRITE},
    {"family", NFTNL_SET_FAMILY, NF_NFTNL_ATTR_TYPE_U32, NF_NFTNL_ATTR_IO_READ | NF_NFTNL_ATTR_IO_WRITE},
    {"id", NFTNL_SET_ID, NF_NFTNL_ATTR_TYPE_U32, NF_NFTNL_ATTR_IO_READ | NF_NFTNL_ATTR_IO_WRITE},
    {"policy", NFTNL_SET_POLICY, NF_NFTNL_ATTR_TYPE_U32, NF_NFTNL_ATTR_IO_READ | NF_NFTNL_ATTR_IO_WRITE},
    {"desc_size", NFTNL_SET_DESC_SIZE, NF_NFTNL_ATTR_TYPE_U32, NF_NFTNL_ATTR_IO_READ | NF_NFTNL_ATTR_IO_WRITE},
    {"timeout", NFTNL_SET_TIMEOUT, NF_NFTNL_ATTR_TYPE_U64, NF_NFTNL_ATTR_IO_READ | NF_NFTNL_ATTR_IO_WRITE},
    {"gc_interval", NFTNL_SET_GC_INTERVAL, NF_NFTNL_ATTR_TYPE_U32, NF_NFTNL_ATTR_IO_READ | NF_NFTNL_ATTR_IO_WRITE},
    {"userdata", NFTNL_SET_USERDATA, NF_NFTNL_ATTR_TYPE_RAW, NF_NFTNL_ATTR_IO_READ | NF_NFTNL_ATTR_IO_WRITE},
    {"obj_type", NFTNL_SET_OBJ_TYPE, NF_NFTNL_ATTR_TYPE_U32, NF_NFTNL_ATTR_IO_READ | NF_NFTNL_ATTR_IO_WRITE},
    {"handle", NFTNL_SET_HANDLE, NF_NFTNL_ATTR_TYPE_U64, NF_NFTNL_ATTR_IO_READ | NF_NFTNL_ATTR_IO_WRITE},
    {NULL}
};

static PyMemberDef NetfilterSetHandle_members[] = {
    {NULL}
};

static PyMethodDef NetfilterSetHandle_methods[] = {
    {"add", (PyCFunction) NetfilterSetHandle_add, METH_VARARGS, NULL},
    {NULL}
};

static PyTypeObject NetfilterSetHandleType = {
    PyVarObject_HEAD_INIT(NULL, 0)
    "libnftnlset.NetfilterSetHandle",          /* tp_name */
    sizeof(NetfilterSetHandle),                /* tp_basicsize */
    0,                                         /* tp_itemsize */
    (destructor) NetfilterSetHandle_dealloc,   /* tp_dealloc */
    0,                                         /* tp_print */
    0,                                         /* tp_getattr */
    0,                                         /* tp_setattr */
    0,                                         /* tp_compare */
    0,                                         /* tp_repr */
    0,                                         /* tp_as_number */
    0,                                         /* tp_as_sequence */
    0,                                         /* tp_as_mapping */
    0,                                         /* tp_hash */
    0,                                         /* tp_call */
    0,                                         /* tp_str */
    (getattrofunc) NetfilterSetHandle_GetAttr, /* tp_getattro */
    (setattrofunc) NetfilterSetHandle_SetAttr, /* tp_setattro */
    0,                                         /* tp_as_buffer */
    Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE,  /* tp_flags */
    "Wrapper for (struct nftnl_set *)",        /* tp_doc */
    0,                                         /* tp_traverse */
    0,                                         /* tp_clear */
    0,                                         /* tp_richcompare */
    0,                                         /* tp_weaklistoffset */
    0,                                         /* tp_iter */
    0,                                         /* tp_iternext */
    NetfilterSetHandle_methods,                /* tp_methods */
    NetfilterSetHandle_members,                /* tp_members */
    0,                                         /* tp_getset */
    0,                                         /* tp_base */
    0,                                         /* tp_dict */
    0,                                         /* tp_descr_get */
    0,                                         /* tp_descr_set */
    0,                                         /* tp_dictoffset */
    (initproc) NetfilterSetHandle_init,        /* tp_init */
    0,                                         /* tp_alloc */
    (newfunc) NetfilterSetHandle_new,          /* tp_new */
};

// END: NetfilterSetHandle

// BEGIN: NetfilterBatchHandle

typedef struct {
    PyObject_HEAD
    uint32_t seq; char* buffer;
    struct mnl_nlmsg_batch *handle;
} NetfilterBatchHandle;

static PyObject* NetfilterBatchHandle_new (PyTypeObject* type, PyTupleObject* args) {
    NetfilterBatchHandle* self;
    self = (NetfilterBatchHandle*) type->tp_alloc(type, 0);
    self->handle = NULL;
    self->buffer = NULL;
    return (PyObject*) self;
}

static int NetfilterBatchHandle_init (NetfilterBatchHandle* self, PyTupleObject* args) {
    return 0;
}

static void NetfilterBatchHandle_dealloc (NetfilterBatchHandle* self) {
    if (self->handle) mnl_nlmsg_batch_stop(self->handle);
    if (self->buffer) free(self->buffer);
    Py_TYPE(self)->tp_free((PyObject*) self);
}

static PyObject* NetfilterBatchHandle_begin (NetfilterBatchHandle* self) {
    if (self->handle || self->buffer) {
        PyErr_SetString(PyExc_OSError, "NetfilterBatchHandle.begin has already been called");
        return NULL;
    }

    self->seq = time(NULL);

    self->buffer = malloc(MNL_SOCKET_BUFFER_SIZE);
    if (!self->buffer) {
        PyErr_SetString(PyExc_OSError, "Call to malloc failed");
        return NULL;
    }

    self->handle = mnl_nlmsg_batch_start(self->buffer, MNL_SOCKET_BUFFER_SIZE);
    if (!self->handle) {
        PyErr_SetString(PyExc_OSError, "Call to mnl_nlmsg_batch_start failed");
        return NULL;
    }

    nftnl_batch_begin(mnl_nlmsg_batch_current(self->handle), self->seq++);
    mnl_nlmsg_batch_next(self->handle);
    Py_RETURN_NONE;
}

static PyObject* NetfilterBatchHandle_set_put (NetfilterBatchHandle* self, PyTupleObject* args) {
    struct nlmsghdr* msg;

    NetfilterSetHandle* set;
    uint16_t family; PyObject* ack;
    uint16_t flags = NLM_F_CREATE | NLM_F_REPLACE;

    if (!PyArg_ParseTuple((PyObject*) args, "OHO", &set, &family, &ack)) {
        PyErr_SetString(PyExc_ValueError, "Parameters must be (NetfilterSetHandle set, uint16_t family, bool ack)");
        return NULL;
    }

    if (!PyObject_IsInstance((PyObject*) set, (PyObject*) &NetfilterSetHandleType)) {
        PyErr_SetString(PyExc_ValueError, "Parameters must be (NetfilterSetHandle set, uint16_t family, bool ack)");
        return NULL;
    }

    if (!PyBool_Check(ack)) {
        PyErr_SetString(PyExc_ValueError, "Parameters must be (NetfilterSetHandle set, uint16_t family, bool ack)");
        return NULL;
    }

    flags |= ((PyObject_IsTrue(ack)) ? (NLM_F_ACK) : (0));

    msg = nftnl_set_nlmsg_build_hdr(mnl_nlmsg_batch_current(self->handle),
                                    NFT_MSG_NEWSET, family, flags,
                                    self->seq++);
    nftnl_set_nlmsg_build_payload(msg, set->handle);
    mnl_nlmsg_batch_next(self->handle);

    Py_RETURN_NONE;
}

static PyObject* NetfilterBatchHandle_set_del (NetfilterBatchHandle* self, PyTupleObject* args) {
    struct nlmsghdr* msg;

    NetfilterSetHandle* set;
    uint16_t family; PyObject* ack;
    uint16_t flags = 0;

    if (!PyArg_ParseTuple((PyObject*) args, "OHO", &set, &family, &ack)) {
        PyErr_SetString(PyExc_ValueError, "Parameters must be (NetfilterSetHandle set, uint16_t family, bool ack)");
        return NULL;
    }

    if (!PyObject_IsInstance((PyObject*) set, (PyObject*) &NetfilterSetHandleType)) {
        PyErr_SetString(PyExc_ValueError, "Parameters must be (NetfilterSetHandle set, uint16_t family, bool ack)");
        return NULL;
    }

    if (!PyBool_Check(ack)) {
        PyErr_SetString(PyExc_ValueError, "Parameters must be (NetfilterSetHandle set, uint16_t family, bool ack)");
        return NULL;
    }

    flags |= ((PyObject_IsTrue(ack)) ? (NLM_F_ACK) : (0));

    msg = nftnl_set_nlmsg_build_hdr(mnl_nlmsg_batch_current(self->handle),
                                    NFT_MSG_DELSET, family, flags,
                                    self->seq++);
    nftnl_set_nlmsg_build_payload(msg, set->handle);
    mnl_nlmsg_batch_next(self->handle);

    Py_RETURN_NONE;
}

static PyObject* NetfilterBatchHandle_elem_put (NetfilterBatchHandle* self, PyTupleObject* args) {
    struct nlmsghdr* msg;

    NetfilterSetHandle* set;
    uint16_t family; PyObject* ack;
    uint16_t flags = NLM_F_CREATE | NLM_F_REPLACE;

    if (!PyArg_ParseTuple((PyObject*) args, "OHO", &set, &family, &ack)) {
        PyErr_SetString(PyExc_ValueError, "Parameters must be (NetfilterSetHandle set, uint16_t family, bool ack)");
        return NULL;
    }

    if (!PyObject_IsInstance((PyObject*) set, (PyObject*) &NetfilterSetHandleType)) {
        PyErr_SetString(PyExc_ValueError, "Parameters must be (NetfilterSetHandle set, uint16_t family, bool ack)");
        return NULL;
    }

    if (!PyBool_Check(ack)) {
        PyErr_SetString(PyExc_ValueError, "Parameters must be (NetfilterSetHandle set, uint16_t family, bool ack)");
        return NULL;
    }

    flags |= ((PyObject_IsTrue(ack)) ? (NLM_F_ACK) : (0));

    msg = nftnl_nlmsg_build_hdr(mnl_nlmsg_batch_current(self->handle),
                                NFT_MSG_NEWSETELEM, family, flags,
                                self->seq++);
    nftnl_set_elems_nlmsg_build_payload(msg, set->handle);
    mnl_nlmsg_batch_next(self->handle);

    Py_RETURN_NONE;
}

static PyObject* NetfilterBatchHandle_elem_del (NetfilterBatchHandle* self, PyTupleObject* args) {
    struct nlmsghdr* msg;

    NetfilterSetHandle* set;
    uint16_t family; PyObject* ack;
    uint16_t flags = 0;

    if (!PyArg_ParseTuple((PyObject*) args, "OHO", &set, &family, &ack)) {
        PyErr_SetString(PyExc_ValueError, "Parameters must be (NetfilterSetHandle set, uint16_t family, bool ack)");
        return NULL;
    }

    if (!PyObject_IsInstance((PyObject*) set, (PyObject*) &NetfilterSetHandleType)) {
        PyErr_SetString(PyExc_ValueError, "Parameters must be (NetfilterSetHandle set, uint16_t family, bool ack)");
        return NULL;
    }

    if (!PyBool_Check(ack)) {
        PyErr_SetString(PyExc_ValueError, "Parameters must be (NetfilterSetHandle set, uint16_t family, bool ack)");
        return NULL;
    }

    flags |= ((PyObject_IsTrue(ack)) ? (NLM_F_ACK) : (0));

    msg = nftnl_nlmsg_build_hdr(mnl_nlmsg_batch_current(self->handle),
                                NFT_MSG_DELSETELEM, family, flags,
                                self->seq++);
    nftnl_set_elems_nlmsg_build_payload(msg, set->handle);
    mnl_nlmsg_batch_next(self->handle);

    Py_RETURN_NONE;
}

static PyObject* NetfilterBatchHandle_dump (NetfilterBatchHandle* self) {
    return PyString_FromStringAndSize(mnl_nlmsg_batch_head(self->handle),
                                      (Py_ssize_t) mnl_nlmsg_batch_size(self->handle));
}

static PyObject* NetfilterBatchHandle_end (NetfilterBatchHandle* self) {
    if (!self->handle || !self->buffer) {
        PyErr_SetString(PyExc_OSError, "NetfilterBatchHandle.begin must be called prior");
        return NULL;
    }

    nftnl_batch_end(mnl_nlmsg_batch_current(self->handle), self->seq++);
    mnl_nlmsg_batch_next(self->handle);
    Py_RETURN_NONE;
}

static PyMemberDef NetfilterBatchHandle_members[] = {
    {NULL}
};

static PyMethodDef NetfilterBatchHandle_methods[] = {
    {"begin", (PyCFunction) NetfilterBatchHandle_begin, METH_NOARGS, NULL},
    {"set_put", (PyCFunction) NetfilterBatchHandle_set_put, METH_VARARGS, NULL},
    {"set_del", (PyCFunction) NetfilterBatchHandle_set_del, METH_VARARGS, NULL},
    {"elem_put", (PyCFunction) NetfilterBatchHandle_elem_put, METH_VARARGS, NULL},
    {"elem_del", (PyCFunction) NetfilterBatchHandle_elem_del, METH_VARARGS, NULL},
    {"dump", (PyCFunction) NetfilterBatchHandle_dump, METH_NOARGS, NULL},
    {"end", (PyCFunction) NetfilterBatchHandle_end, METH_NOARGS, NULL},
    {NULL}
};

static PyTypeObject NetfilterBatchHandleType = {
    PyVarObject_HEAD_INIT(NULL, 0)
    "libnftnlset.NetfilterBatchHandle",            /* tp_name */
    sizeof(NetfilterBatchHandle),                  /* tp_basicsize */
    0,                                             /* tp_itemsize */
    (destructor) NetfilterBatchHandle_dealloc,     /* tp_dealloc */
    0,                                             /* tp_print */
    0,                                             /* tp_getattr */
    0,                                             /* tp_setattr */
    0,                                             /* tp_compare */
    0,                                             /* tp_repr */
    0,                                             /* tp_as_number */
    0,                                             /* tp_as_sequence */
    0,                                             /* tp_as_mapping */
    0,                                             /* tp_hash */
    0,                                             /* tp_call */
    0,                                             /* tp_str */
    0,                                             /* tp_getattro */
    0,                                             /* tp_setattro */
    0,                                             /* tp_as_buffer */
    Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE,      /* tp_flags */
    "Wrapper for (struct mnl_nlmsg_batch *)",      /* tp_doc */
    0,                                             /* tp_traverse */
    0,                                             /* tp_clear */
    0,                                             /* tp_richcompare */
    0,                                             /* tp_weaklistoffset */
    0,                                             /* tp_iter */
    0,                                             /* tp_iternext */
    NetfilterBatchHandle_methods,                  /* tp_methods */
    NetfilterBatchHandle_members,                  /* tp_members */
    0,                                             /* tp_getset */
    0,                                             /* tp_base */
    0,                                             /* tp_dict */
    0,                                             /* tp_descr_get */
    0,                                             /* tp_descr_set */
    0,                                             /* tp_dictoffset */
    (initproc) NetfilterBatchHandle_init,          /* tp_init */
    0,                                             /* tp_alloc */
    (newfunc) NetfilterBatchHandle_new,            /* tp_new */
};

// END: NetfilterBatchHandle

static PyObject* libnftnlset_element (PyObject* self) {
    PyObject* empty;
    NetfilterElementHandle* handle_object;
    struct nftnl_set_elem* handle_struct;

    handle_struct = nftnl_set_elem_alloc();
    if (!handle_struct) {
        PyErr_SetString(PyExc_OSError, "Call to nftnl_set_elem_alloc failed");
        return NULL;
    }

    empty = PyTuple_New(0);
    handle_object = (NetfilterElementHandle*) PyObject_CallObject((PyObject*) &NetfilterElementHandleType, empty);
    Py_DECREF(empty);

    handle_object->handle = handle_struct;

    return (PyObject*) handle_object;
}

static PyObject* libnftnlset_set (PyObject* self, PyTupleObject* args) {
    PyObject* empty;
    NetfilterSetHandle* handle_object;
    struct nftnl_set* handle_struct;

    handle_struct = nftnl_set_alloc();
    if (!handle_struct) {
        PyErr_SetString(PyExc_OSError, "Call to nftnl_set_alloc failed");
        return NULL;
    }

    empty = PyTuple_New(0);
    handle_object = (NetfilterSetHandle*) PyObject_CallObject((PyObject*) &NetfilterSetHandleType, empty);
    Py_DECREF(empty);

    handle_object->handle = handle_struct;

    return (PyObject*) handle_object;
}

static PyObject* libnftnlset_batch (PyObject* self, PyTupleObject* args) {
    PyObject* empty;
    NetfilterBatchHandle* handle_object;

    empty = PyTuple_New(0);
    handle_object = (NetfilterBatchHandle*) PyObject_CallObject((PyObject*) &NetfilterBatchHandleType, empty);
    Py_DECREF(empty);

    return (PyObject*) handle_object;
}

static PyMethodDef libnftnlset_methods[] = {
    {"element", (PyCFunction) libnftnlset_element, METH_NOARGS, NULL},
    {"set", (PyCFunction) libnftnlset_set, METH_NOARGS, NULL},
    {"batch", (PyCFunction) libnftnlset_batch, METH_NOARGS, NULL},
    {NULL}
};

PyMODINIT_FUNC initlibnftnlset (void) {
    PyObject* module;
    PyObject* attrs;

    if (PyType_Ready(&NetfilterElementHandleType) < 0)
        return;
    if (PyType_Ready(&NetfilterSetHandleType) < 0)
        return;
    if (PyType_Ready(&NetfilterBatchHandleType) < 0)
        return;

    module = Py_InitModule("libnftnlset", libnftnlset_methods);
    if (module == NULL)
        return;

    /* Classes */

    Py_INCREF((PyObject*) &NetfilterElementHandleType);
    PyModule_AddObject(module, "NetfilterElementHandle", (PyObject*) &NetfilterElementHandleType);

    Py_INCREF((PyObject*) &NetfilterSetHandleType);
    PyModule_AddObject(module, "NetfilterSetHandle", (PyObject*) &NetfilterSetHandleType);

    Py_INCREF((PyObject*) &NetfilterBatchHandleType);
    PyModule_AddObject(module, "NetfilterBatchHandle", (PyObject*) &NetfilterBatchHandleType);

    /* Protocol */

    PyModule_AddIntConstant(module, "NFPROTO_IPV4", NFPROTO_IPV4);
    PyModule_AddIntConstant(module, "NFPROTO_IPV6", NFPROTO_IPV6);
    PyModule_AddIntConstant(module, "NFPROTO_BRIDGE", NFPROTO_BRIDGE);
    PyModule_AddIntConstant(module, "NFPROTO_ARP", NFPROTO_ARP);

    /* Socket */

    PyModule_AddIntConstant(module, "MNL_SOCKET_AUTOPID", MNL_SOCKET_AUTOPID);
    PyModule_AddIntConstant(module, "MNL_SOCKET_BUFFER_SIZE", MNL_SOCKET_BUFFER_SIZE);

    /* Subsystem */

    PyModule_AddIntConstant(module, "NETLINK_NETFILTER", NETLINK_NETFILTER);

    /* Attributes */

    attrs = _nf_nftnl_attr_spec_dict_new(NetfilterElementHandleAttributes);
    PyModule_AddObject(module, "NFT_ATTR_SPECS_ELEM", attrs);
    NetfilterElementHandleAttributesDict = attrs;

    attrs = _nf_nftnl_attr_spec_dict_new(NetfilterSetHandleAttributes);
    PyModule_AddObject(module, "NFT_ATTR_SPECS_SET", attrs);
    NetfilterSetHandleAttributesDict = attrs;
}
