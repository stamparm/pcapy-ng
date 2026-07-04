/*
 * Copyright (c) 2021 Miroslav Stampar (miroslav@sqlmap.org)
 * Copyright (c) 2014 CORE Security Technologies
 *
 * This software is provided under under the Apache Software License.
 * See the accompanying LICENSE file for more information.
 *
 */

#define PY_SSIZE_T_CLEAN

#include <Python.h>
#include <pcap.h>

#include "pcapobj.h"
#include "pcapy.h"
#include "pcapdumper.h"
#include "pcap_pkthdr.h"

#ifdef WIN32
#include <winsock2.h>
#else
#include <netinet/in.h>
#endif

#if defined(__linux__)
#include <sys/socket.h>
#include <linux/if_packet.h>   /* PACKET_FANOUT, PACKET_FANOUT_HASH, SOL_PACKET */
#endif


// internal pcapobject
typedef struct {
	PyObject_HEAD
	pcap_t *pcap;
	bpf_u_int32 net;
	bpf_u_int32 mask;
	/* F5: live per-class counters for loop_filtered, pollable mid-loop via filtered_stats().
	   [0]=admitted [1]=dropped [2..]=per-class-index counts (3 generic, up to 6 security) */
	unsigned long long filt_counts[8];
	int filt_profile;   /* profile of the last loop_filtered run (0 generic, 1 security) */
} pcapobject;


// PcapType

static PyObject*
p_close(pcapobject* pp, PyObject*)
{
  if ( pp->pcap )
    pcap_close(pp->pcap);

  pp->pcap = NULL;

  Py_RETURN_NONE;
}

static void
pcap_dealloc(pcapobject* pp)
{
  p_close(pp, NULL);

  PyObject_Del(pp);
}

static PyObject *
err_closed(void)
{
  PyErr_SetString(PyExc_ValueError, "pcap is closed");
  return NULL;
}

// pcap methods
static PyObject* p_getnet(pcapobject* pp, PyObject* args);
static PyObject* p_getmask(pcapobject* pp, PyObject* args);
static PyObject* p_setfilter( pcapobject* pp, PyObject* args );
static PyObject* p_next(pcapobject* pp, PyObject*);
static PyObject* p_dispatch(pcapobject* pp, PyObject* args);
static PyObject* p_loop(pcapobject* pp, PyObject* args);
static PyObject* p_datalink(pcapobject* pp, PyObject* args);
static PyObject* p_setdirection(pcapobject* pp, PyObject* args);
static PyObject* p_setnonblock(pcapobject* pp, PyObject* args);
static PyObject* p_getnonblock(pcapobject* pp, PyObject* args);
static PyObject* p_dump_open(pcapobject* pp, PyObject* args);
static PyObject* p_sendpacket(pcapobject* pp, PyObject* args);
static PyObject* p_stats( pcapobject* pp, PyObject*);
static PyObject* p__enter__( pcapobject* pp, PyObject*);
static PyObject* p_getfd(pcapobject* pp, PyObject* args);
static PyObject* p_set_fanout(pcapobject* pp, PyObject* args);
static PyObject* p_set_snaplen(pcapobject* pp, PyObject* args);
static PyObject* p_set_promisc(pcapobject* pp, PyObject* args);
static PyObject* p_set_timeout(pcapobject* pp, PyObject* args);
static PyObject* p_set_buffer_size(pcapobject* pp, PyObject* args);
static PyObject* p_set_rfmon(pcapobject* pp, PyObject* args);
static PyObject* p_activate(pcapobject* pp, PyObject* args);
static PyObject* p_loop_filtered(pcapobject* pp, PyObject* args);
static PyObject* p_filtered_stats(pcapobject* pp, PyObject*);
static PyObject* p_loop_to_buffer(pcapobject* pp, PyObject* args);
static PyObject* p_next_batch(pcapobject* pp, PyObject* args);

static PyMethodDef p_methods[] = {
  {"loop", (PyCFunction) p_loop, METH_VARARGS, "loops packet dispatching"},
  {"loop_filtered", (PyCFunction) p_loop_filtered, METH_VARARGS, "loop_filtered(cnt, cb, admit_mask=7, addr_set=b'', flow_cutoff=0, dpi_ports=None, tls_ports=None, dns_port=53, l2_offset=14, profile=0): classify each packet in C and invoke cb(hdr, data, cls) ONLY for admitted classes (admit_mask is a bitmask over class indices); dropped classes never build a Python object. GENERIC profile (default) classes: 0=OTHER, 1=FLOW_HEAD (within first flow_cutoff packets of a flow -- BPF can't track flows), 2=SET_MATCH (src/dst in addr_set, a packed 4-byte network-order IPv4 set of any size -- BPF can't hold large sets). l2_offset is where the IPv4 header begins (Ethernet=14, LINUX_SLL=16, DLT_RAW=0); VLAN tags are skipped. profile=1 selects a built-in security classifier (classes 100..105: DNS/HTTP/noise/IP-set/handshake/SYN) using dns_port/dpi_ports/tls_ports. Returns (admitted, dropped, <per-class counts>)."},
  {"filtered_stats", (PyCFunction) p_filtered_stats, METH_NOARGS, "filtered_stats(): live counter snapshot of the current/last loop_filtered run, safe to poll from another thread. Returns (admitted, dropped, <per-class counts>) matching the active profile."},
  {"loop_to_buffer", (PyCFunction) p_loop_to_buffer, METH_VARARGS, "loop_to_buffer(cnt, writable_buf, admit_mask=7, addr_set=b'', flow_cutoff=0, dpi_ports=None, tls_ports=None, dns_port=53, l2_offset=14, profile=0): same classification as loop_filtered, but writes admitted packets into writable_buf (e.g. a multiprocessing.shared_memory buffer) as [u32 caplen LE][u8 class][caplen bytes] with the GIL released for the whole loop (no per-packet Python); worker processes drain it in parallel. Returns (written, dropped, overflow, bytes_used, <per-class counts>)."},
  {"next_batch", (PyCFunction) p_next_batch, METH_VARARGS, "next_batch(max_n): capture up to max_n packets in ONE call; returns (packet_bytes, packed_meta) where packed_meta is an array of 16-byte records, one per packet, each four native-endian uint32 (sec, usec, offset, caplen); offset/caplen slice the packet out of packet_bytes. Empty packed_meta = EOF/timeout. Amortizes the per-packet C<->Python boundary."},
  {"dispatch", (PyCFunction) p_dispatch, METH_VARARGS, "dispatchs packets"},
  {"next", (PyCFunction) p_next, METH_NOARGS, "returns next packet"},
  {"setfilter", (PyCFunction) p_setfilter, METH_VARARGS, "compiles and sets a BPF capture filter"},
  {"getnet", (PyCFunction) p_getnet, METH_VARARGS, "returns the network address for the device"},
  {"getmask", (PyCFunction) p_getmask, METH_VARARGS, "returns the netmask for the device"},
  {"datalink", (PyCFunction) p_datalink, METH_VARARGS, "returns the link layer type"},
  {"getnonblock", (PyCFunction) p_getnonblock, METH_VARARGS, "returns the current `non-blocking' state"},
  {"setnonblock", (PyCFunction) p_setnonblock, METH_VARARGS, "puts into `non-blocking' mode, or take it out, depending on the argument"},
  {"setdirection", (PyCFunction) p_setdirection, METH_VARARGS, "set the direction for which packets will be captured"},
  {"dump_open", (PyCFunction) p_dump_open, METH_VARARGS, "creates a dumper object"},
  {"sendpacket", (PyCFunction) p_sendpacket, METH_VARARGS, "sends a packet through the interface"},
  {"stats", (PyCFunction) p_stats, METH_NOARGS, "returns capture statistics"},
  {"close", (PyCFunction) p_close, METH_NOARGS, "close the capture"},
  {"set_snaplen", (PyCFunction)p_set_snaplen, METH_VARARGS, "set the snapshot length for a not-yet-activated capture handle"},
  {"set_promisc", (PyCFunction)p_set_promisc, METH_VARARGS, "set promiscuous mode for a not-yet-activated capture handle"},
  {"set_timeout", (PyCFunction)p_set_timeout, METH_VARARGS, "set the read timeout for a not-yet-activated capture handle"},
  {"set_buffer_size", (PyCFunction)p_set_buffer_size, METH_VARARGS, "set the buffer size for a not-yet-activated capture handle"},
  {"activate", (PyCFunction)p_activate, METH_NOARGS, "activate a capture handle created using create()"},
  {"__enter__", (PyCFunction) p__enter__, METH_NOARGS, NULL},
  {"__exit__", (PyCFunction) p_close, METH_VARARGS, NULL},
#ifndef WIN32
  {"getfd", (PyCFunction) p_getfd, METH_VARARGS, "get selectable pcap fd"},
  {"set_fanout", (PyCFunction) p_set_fanout, METH_VARARGS, "set_fanout(group_id, fanout_type=PACKET_FANOUT_HASH): Linux only. Join this (live, activated) capture's AF_PACKET socket to a PACKET_FANOUT group so the kernel load-balances one interface's packets across every capture handle sharing the same group_id. Open N handles, set_fanout(g) on each, and run N capture loops to scale capture past one thread (each flow stays on one handle with PACKET_FANOUT_HASH). Raises on non-Linux or a non-live handle."},
  {"set_rfmon", (PyCFunction)p_set_rfmon, METH_VARARGS, "set monitor mode for a not-yet-activated capture handle"}, /* Available on Npcap, not on Winpcap. */
#endif
  {NULL, NULL}	/* sentinel */
};

static PyObject*
pcap_getattr(pcapobject* pp, char* name)
{
#if PY_MAJOR_VERSION >= 3
  PyObject *nameobj = PyUnicode_FromString(name);
  PyObject *attr = PyObject_GenericGetAttr((PyObject *)pp, nameobj);
  Py_DECREF(nameobj);
  return attr;
#else
  return Py_FindMethod(p_methods, (PyObject*)pp, name);
#endif
}


PyTypeObject Pcaptype = {
#if PY_MAJOR_VERSION >= 3
  PyVarObject_HEAD_INIT(&PyType_Type, 0)
  "Reader",                  /* tp_name */
  sizeof(pcapobject),        /* tp_basicsize */
  0,                         /* tp_itemsize */
  (destructor)pcap_dealloc,  /* tp_dealloc */
  0,                         /* tp_print */
  (getattrfunc)pcap_getattr, /* tp_getattr */
  0,                         /* tp_setattr */
  0,                         /* tp_reserved */
  0,                         /* tp_repr */
  0,                         /* tp_as_number */
  0,                         /* tp_as_sequence */
  0,                         /* tp_as_mapping */
  0,                         /* tp_hash */
  0,                         /* tp_call */
  0,                         /* tp_str */
  0,                         /* tp_getattro */
  0,                         /* tp_setattro */
  0,                         /* tp_as_buffer */
  Py_TPFLAGS_DEFAULT,        /* tp_flags */
  NULL,                      /* tp_doc */
  0,                         /* tp_traverse */
  0,                         /* tp_clear */
  0,                         /* tp_richcompare */
  0,                         /* tp_weaklistoffset */
  0,                         /* tp_iter */
  0,                         /* tp_iternext */
  p_methods,                 /* tp_methods */
  0,                         /* tp_members */
  0,                         /* tp_getset */
  0,                         /* tp_base */
  0,                         /* tp_dict */
  0,                         /* tp_descr_get */
  0,                         /* tp_descr_set */
  0,                         /* tp_dictoffset */
  0,                         /* tp_init */
  0,                         /* tp_alloc */
  0,                         /* tp_new */
#else
  PyObject_HEAD_INIT(NULL)
  0,
  "Reader",
  sizeof(pcapobject),
  0,
  /* methods */
  (destructor)pcap_dealloc,    /* tp_dealloc*/
  0,                           /* tp_print*/
  (getattrfunc)pcap_getattr,   /* tp_getattr*/
  0,                           /* tp_setattr*/
  0,                           /* tp_compare*/
  0,                           /* tp_repr*/
  0,                           /* tp_as_number*/
  0,                           /* tp_as_sequence*/
  0,                           /* tp_as_mapping*/
  0,                           /* tp_hash */
  0,                           /* tp_call */
  0,                           /* tp_str */
  0,                           /* tp_getattro */
  0,                           /* tp_setattro */
  0,                           /* tp_as_buffer */
  Py_TPFLAGS_DEFAULT,          /* tp_flags */
  NULL,                        /* tp_doc */
  0,                           /* tp_traverse */
  0,                           /* tp_clear */
  0,                           /* tp_richcompare */
  0,                           /* tp_weaklistoffset */
  0,                           /* tp_iter */
  0,                           /* tp_iternext */
  p_methods,                   /* tp_methods */
  0,                           /* tp_members */
  0,                           /* tp_getset */
  0,                           /* tp_base */
  0,                           /* tp_dict */
  0,                           /* tp_descr_get */
  0,                           /* tp_descr_set */
  0,                           /* tp_dictoffset */
  0,                           /* tp_init */
  0,                           /* tp_alloc */
  0,                           /* tp_new */
#endif
};


PyObject*
new_pcapobject(pcap_t *pcap, bpf_u_int32 net, bpf_u_int32 mask)
{
  if (PyType_Ready(&Pcaptype) < 0)
    return NULL;

  pcapobject *pp;

  pp = PyObject_New(pcapobject, &Pcaptype);
  if (pp == NULL)
    return NULL;

  pp->pcap = pcap;
  pp->net = net;
  pp->mask = mask;

  return (PyObject*)pp;
}

static void ntos(char* dst, unsigned int n, int ip)
{
  ip = htonl(ip);
  snprintf(dst, n, "%i.%i.%i.%i",
	   ((ip >> 24) & 0xFF),
	   ((ip >> 16) & 0xFF),
	   ((ip >> 8) & 0xFF),
	   (ip & 0xFF));
}

static PyObject*
p_getnet(pcapobject* pp, PyObject* args)
{
  if (Py_TYPE(pp) != &Pcaptype)
    {
      PyErr_SetString(PcapError, "Not a pcap object");
      return NULL;
    }

  if (!pp->pcap)
    return err_closed();

  char ip_str[20];
  ntos(ip_str, sizeof(ip_str), pp->net);
  return Py_BuildValue("s", ip_str);
}

static PyObject*
p_getmask(pcapobject* pp, PyObject* args)
{
  if (Py_TYPE(pp) != &Pcaptype)
    {
      PyErr_SetString(PcapError, "Not a pcap object");
      return NULL;
    }

  if (!pp->pcap)
    return err_closed();

  char ip_str[20];
  ntos(ip_str, sizeof(ip_str), pp->mask);
  return Py_BuildValue("s", ip_str);
}

static PyObject*
p_setfilter(pcapobject* pp, PyObject* args)
{
  struct bpf_program bpfprog;
  int status;
  char* str;

  if (Py_TYPE(pp) != &Pcaptype)
    {
      PyErr_SetString(PcapError, "Not a pcap object");
	return NULL;
    }

  if (!pp->pcap)
    return err_closed();

  if (!PyArg_ParseTuple(args,"s:setfilter",&str))
    return NULL;

  status = pcap_compile(pp->pcap, &bpfprog, str, 1, pp->mask);
  if (status)
    {
      PyErr_SetString(PcapError, pcap_geterr(pp->pcap));
      return NULL;
    }

  status = pcap_setfilter(pp->pcap, &bpfprog);
  if (status)
    {
      PyErr_SetString(PcapError, pcap_geterr(pp->pcap));
      return NULL;
    }

  Py_INCREF(Py_None);
  return Py_None;
}

static PyObject*
p_next(pcapobject* pp, PyObject*)
{
  struct pcap_pkthdr *hdr = NULL;
  const unsigned char *buf = (const unsigned char*)"";
  int err_code = 1;

  if (Py_TYPE(pp) != &Pcaptype)
  {
    PyErr_SetString(PcapError, "Not a pcap object");
    return NULL;
  }

  if (!pp->pcap)
    return err_closed();

  // allow threads as this might block
  Py_BEGIN_ALLOW_THREADS;
  err_code = pcap_next_ex(pp->pcap, &hdr, &buf);
  Py_END_ALLOW_THREADS;

  if(err_code == -1)
  {
    PyErr_SetString(PcapError, pcap_geterr(pp->pcap));
    return NULL;
  }


  PyObject *pkthdr;
  int _caplen = 0;
  if (err_code == 1) {
    pkthdr = new_pcap_pkthdr(hdr);
    _caplen = hdr->caplen;
  } else {
    pkthdr = Py_None;
    Py_INCREF(pkthdr);
    _caplen = 0;
  }


  if (pkthdr)
  {
    PyObject *ret = NULL;

    #if PY_MAJOR_VERSION >= 3
      /* return bytes */
      ret = Py_BuildValue("(Oy#)", pkthdr, buf, _caplen);
    #else
      ret = Py_BuildValue("(Os#)", pkthdr, buf, _caplen);
    #endif

    Py_DECREF(pkthdr);
    return ret;
  }

  PyErr_SetString(PcapError, "Can't build pkthdr");
  return NULL;
}

struct PcapCallbackContext {
  PcapCallbackContext(pcap_t* p, PyObject* f, PyThreadState* ts)
    : ppcap_t(p), pyfunc(f), thread_state(ts)
  {
    Py_INCREF(pyfunc);
  }
  ~PcapCallbackContext()
  {
    Py_DECREF(pyfunc);
  }

  pcap_t* ppcap_t;
  PyObject *pyfunc;
  PyThreadState *thread_state;

};


static void
PythonCallBack(u_char *user,
	       const struct pcap_pkthdr *header,
	       const u_char *packetdata)
{
  PyObject *arglist, *result;
  unsigned int *len;
  PcapCallbackContext *pctx;
  len    = (unsigned int *)&header->caplen;
  pctx = (PcapCallbackContext *)user;

  PyEval_RestoreThread(pctx->thread_state);

  PyObject *hdr = new_pcap_pkthdr(header);

#if PY_MAJOR_VERSION >= 3
  /* pass bytes */
  arglist = Py_BuildValue("Oy#", hdr, packetdata, *len);
#else
  arglist = Py_BuildValue("Os#", hdr, packetdata, *len);
#endif

  result = PyObject_CallObject(pctx->pyfunc,arglist);

  Py_XDECREF(arglist);
  if (result)
    Py_DECREF(result);

  Py_DECREF(hdr);

  if (!result)
    pcap_breakloop(pctx->ppcap_t);

  PyEval_SaveThread();
}

static PyObject*
p_dispatch(pcapobject* pp, PyObject* args)
{
  int cant, ret;
  PyObject *PyFunc;

  if (Py_TYPE(pp) != &Pcaptype)
    {
      PyErr_SetString(PcapError, "Not a pcap object");
      return NULL;
    }

  if (!pp->pcap)
    return err_closed();

  if(!PyArg_ParseTuple(args,"iO:dispatch",&cant,&PyFunc))
    return NULL;

  PcapCallbackContext ctx(pp->pcap, PyFunc, PyThreadState_Get());
  PyEval_SaveThread();
  ret = pcap_dispatch(pp->pcap, cant, PythonCallBack, (u_char*)&ctx);
  PyEval_RestoreThread(ctx.thread_state);

  // Fix: Check if a Python exception occurred inside the callback
  if (PyErr_Occurred()) {
      return NULL;
  }

  if(ret<0) {
    if (ret!=-2)
      /* pcap error, pcap_breakloop was not called so error is not set */
      PyErr_SetString(PcapError, pcap_geterr(pp->pcap));
    return NULL; // This handles the error case correctly now
  }

  return Py_BuildValue("i", ret);
}

static PyObject*
p_stats(pcapobject* pp, PyObject*)
{
  if (Py_TYPE(pp) != &Pcaptype)
     {
	   PyErr_SetString(PcapError, "Not a pcap object");
	   return NULL;
	 }

  if (!pp->pcap)
    return err_closed();

  struct pcap_stat stats;

  if (-1 == pcap_stats(pp->pcap, &stats)) {
     PyErr_SetString(PcapError, pcap_geterr(pp->pcap));
	 return NULL;
  }

	return Py_BuildValue("III", stats.ps_recv, stats.ps_drop, stats.ps_ifdrop);
}

static PyObject*
p__enter__( pcapobject* pp, PyObject*)
{
  if (Py_TYPE(pp) != &Pcaptype)
    {
      PyErr_SetString(PcapError, "Not a pcap object");
      return NULL;
    }

  if (!pp->pcap)
    return err_closed();

  Py_INCREF(pp);
  return (PyObject*)pp;
}

static PyObject*
p_dump_open(pcapobject* pp, PyObject* args)
{
  char *filename;
  pcap_dumper_t *ret;

  if (Py_TYPE(pp) != &Pcaptype)
    {
      PyErr_SetString(PcapError, "Not a pcap object");
      return NULL;
    }

  if (!pp->pcap)
    return err_closed();

  if(!PyArg_ParseTuple(args,"s",&filename))
    return NULL;

  ret = pcap_dump_open(pp->pcap, filename);

  if (ret==NULL) {
    PyErr_SetString(PcapError, pcap_geterr(pp->pcap));
    return NULL;
  }

  return new_pcapdumper(ret);
}


static PyObject*
p_loop(pcapobject* pp, PyObject* args)
{
  int cant, ret;
  PyObject *PyFunc;

  if (Py_TYPE(pp) != &Pcaptype)
    {
      PyErr_SetString(PcapError, "Not a pcap object");
      return NULL;
    }

  if (!pp->pcap)
    return err_closed();

  if(!PyArg_ParseTuple(args,"iO:loop",&cant,&PyFunc))
    return NULL;

  PcapCallbackContext ctx(pp->pcap, PyFunc, PyThreadState_Get());
  PyEval_SaveThread();
  ret = pcap_loop(pp->pcap, cant, PythonCallBack, (u_char*)&ctx);
  PyEval_RestoreThread(ctx.thread_state);

  if(ret<0) {
    if (ret!=-2)
      /* pcap error, pcap_breakloop was not called so error is not set */
      PyErr_SetString(PcapError, pcap_geterr(pp->pcap));
    return NULL;
  }

  Py_INCREF(Py_None);
  return Py_None;
}


static PyObject*
p_datalink(pcapobject* pp, PyObject* args)
{
	if (Py_TYPE(pp) != &Pcaptype) {
		PyErr_SetString(PcapError, "Not a pcap object");
		return NULL;
	}

	if (!pp->pcap)
		return err_closed();

	int type = pcap_datalink(pp->pcap);

	return Py_BuildValue("i", type);
}

static PyObject*
p_setdirection(pcapobject* pp, PyObject* args)
{
	if (Py_TYPE(pp) != &Pcaptype) {
		PyErr_SetString(PcapError, "Not a pcap object");
		return NULL;
	}

	if (!pp->pcap)
		return err_closed();

	pcap_direction_t direction;

	if (!PyArg_ParseTuple(args, "i", &direction))
		return NULL;

	int ret = pcap_setdirection(pp->pcap, direction);
	if (-1 == ret) {
		PyErr_SetString(PcapError, "Failed setting direction");
		return NULL;
	}

	Py_INCREF(Py_None);
	return Py_None;
}

static PyObject*
p_setnonblock(pcapobject* pp, PyObject* args)
{
	if (Py_TYPE(pp) != &Pcaptype) {
		PyErr_SetString(PcapError, "Not a pcap object");
		return NULL;
	}

	if (!pp->pcap)
		return err_closed();

	int state;

	if (!PyArg_ParseTuple(args, "i", &state))
		return NULL;

	char errbuf[PCAP_ERRBUF_SIZE];
	int ret = pcap_setnonblock(pp->pcap, state, errbuf);
	if (-1 == ret) {
		PyErr_SetString(PcapError, errbuf);
		return NULL;
	}

	Py_INCREF(Py_None);
	return Py_None;
}

static PyObject*
p_getnonblock(pcapobject* pp, PyObject* args)
{
	if (Py_TYPE(pp) != &Pcaptype) {
		PyErr_SetString(PcapError, "Not a pcap object");
		return NULL;
	}

	if (!pp->pcap)
		return err_closed();

	char errbuf[PCAP_ERRBUF_SIZE];
	int state = pcap_getnonblock(pp->pcap, errbuf);
	if (-1 == state) {
		PyErr_SetString(PcapError, errbuf);
		return NULL;
	}

	return Py_BuildValue("i", state);
}

static PyObject*
p_set_snaplen(pcapobject* pp, PyObject* args)
{
	if (Py_TYPE(pp) != &Pcaptype) {
		PyErr_SetString(PcapError, "Not a pcap object");
		return NULL;
	}

	if (!pp->pcap)
		return err_closed();

	int snaplen;

	if (!PyArg_ParseTuple(args, "i", &snaplen))
		return NULL;

	int ret = pcap_set_snaplen(pp->pcap, snaplen);
	return Py_BuildValue("i", ret);
}

static PyObject*
p_set_promisc(pcapobject* pp, PyObject* args)
{
	if (Py_TYPE(pp) != &Pcaptype) {
		PyErr_SetString(PcapError, "Not a pcap object");
		return NULL;
	}

	if (!pp->pcap)
		return err_closed();

	int promisc;

	if (!PyArg_ParseTuple(args, "i", &promisc))
		return NULL;

	int ret = pcap_set_promisc(pp->pcap, promisc);
	return Py_BuildValue("i", ret);
}

static PyObject*
p_set_timeout(pcapobject* pp, PyObject* args)
{
	if (Py_TYPE(pp) != &Pcaptype) {
		PyErr_SetString(PcapError, "Not a pcap object");
		return NULL;
	}

	if (!pp->pcap)
		return err_closed();

	int to_ms;

	if (!PyArg_ParseTuple(args, "i", &to_ms))
		return NULL;

	int ret = pcap_set_timeout(pp->pcap, to_ms);
	return Py_BuildValue("i", ret);
}

static PyObject*
p_set_buffer_size(pcapobject* pp, PyObject* args)
{
	if (Py_TYPE(pp) != &Pcaptype) {
		PyErr_SetString(PcapError, "Not a pcap object");
		return NULL;
	}

	if (!pp->pcap)
		return err_closed();

	int buffer_size;

	if (!PyArg_ParseTuple(args, "i", &buffer_size))
		return NULL;

	int ret = pcap_set_buffer_size(pp->pcap, buffer_size);
	return Py_BuildValue("i", ret);
}

static PyObject*
p_set_rfmon(pcapobject* pp, PyObject* args)
{
	if (Py_TYPE(pp) != &Pcaptype) {
		PyErr_SetString(PcapError, "Not a pcap object");
		return NULL;
	}

	if (!pp->pcap)
		return err_closed();

	int rfmon;

	if (!PyArg_ParseTuple(args, "i", &rfmon))
		return NULL;

	int ret = pcap_set_rfmon(pp->pcap, rfmon);
	return Py_BuildValue("i", ret);
}

static PyObject*
p_activate(pcapobject* pp, PyObject*)
{
	if (Py_TYPE(pp) != &Pcaptype) {
		PyErr_SetString(PcapError, "Not a pcap object");
		return NULL;
	}

	if (!pp->pcap)
		return err_closed();

	int ret = pcap_activate(pp->pcap);
	return Py_BuildValue("i", ret);
}


static PyObject*
p_sendpacket(pcapobject* pp, PyObject* args)
{
  int status;
  unsigned char* str;
  Py_ssize_t length;

  if (Py_TYPE(pp) != &Pcaptype)
    {
      PyErr_SetString(PcapError, "Not a pcap object");
      return NULL;
    }

  if (!pp->pcap)
    return err_closed();

#if PY_MAJOR_VERSION >= 3
  /* accept bytes */
  if (!PyArg_ParseTuple(args,"y#", &str, &length)) {
    return NULL;
  }
#else
  if (!PyArg_ParseTuple(args,"s#", &str, &length)) {
    return NULL;
  }
#endif


  status = pcap_sendpacket(pp->pcap, str, length);
  if (status)
    {
      PyErr_SetString(PcapError, pcap_geterr(pp->pcap));
      return NULL;
    }

  Py_INCREF(Py_None);
  return Py_None;
}

#ifndef WIN32
static PyObject*
p_getfd(pcapobject* pp, PyObject* args)
{
  if (Py_TYPE(pp) != &Pcaptype)
    {
      PyErr_SetString(PcapError, "Not a pcap object");
      return NULL;
    }

  if (!pp->pcap)
    return err_closed();

  int fd = pcap_get_selectable_fd(pp->pcap);
  return Py_BuildValue("i", fd);
}
#endif

/* set_fanout(group_id, fanout_type=PACKET_FANOUT_HASH): join this live AF_PACKET capture to a
   kernel PACKET_FANOUT group so one interface's traffic is load-balanced across every handle in
   the same group. Linux-only; needs a live, activated handle (pcap_fileno gives the socket fd). */
static PyObject*
p_set_fanout(pcapobject* pp, PyObject* args)
{
  if (Py_TYPE(pp) != &Pcaptype)
    {
      PyErr_SetString(PcapError, "Not a pcap object");
      return NULL;
    }

  if (!pp->pcap)
    return err_closed();

#if defined(__linux__) && defined(PACKET_FANOUT)
  int group_id;
  int fanout_type = PACKET_FANOUT_HASH;

  if (!PyArg_ParseTuple(args, "i|i:set_fanout", &group_id, &fanout_type))
    return NULL;

  int fd = pcap_fileno(pp->pcap);
  if (fd < 0)
    {
      PyErr_SetString(PcapError, "no socket fd for this capture (PACKET_FANOUT needs a live AF_PACKET capture, not an offline pcap)");
      return NULL;
    }

  int arg = (group_id & 0xffff) | (fanout_type << 16);
  if (setsockopt(fd, SOL_PACKET, PACKET_FANOUT, &arg, sizeof(arg)) < 0)
    {
      PyErr_SetFromErrno(PcapError);
      return NULL;
    }

  Py_INCREF(Py_None);
  return Py_None;
#else
  (void) args;
  PyErr_SetString(PcapError, "PACKET_FANOUT is only available on Linux");
  return NULL;
#endif
}

/* ---- pcapy-ng FAST: in-C severity classify + admit (generic prefilter) ---- */
/* hand-coded fast classifier: 0=DNS (port dns_port), 1=DPI (PSH on dpi_ports), 2=noise.
   Ports are configurable per loop_filtered() call so the consumer can match its own
   capture filter (Maltrail's CAPTURE_FILTER) instead of a hardcoded set. */
static const unsigned short MT_DPI_PORTS_DEFAULT[] = {80, 8080, 3128, 8000, 8118, 1080};
static const unsigned short MT_TLS_PORTS_DEFAULT[] = {443};

struct mt_classcfg {
  unsigned short dns_port;            /* default 53 */
  const unsigned short* dpi_ports;    /* TCP PSH on any of these -> DPI (class 1) */
  unsigned int ndpi;
  const unsigned short* tls_ports;    /* flow-cutoff head capture on these -> HEAD (class 4) */
  unsigned int ntls;
  unsigned int l2_off;                /* byte offset where the IPv4 header begins: Ethernet=14,
                                         LINUX_SLL=16, LINUX_SLL2=20, DLT_RAW/null=0 */
  int profile;                        /* 0 = generic (OTHER/FLOW_HEAD/SET_MATCH); 1 = security */
};
/* Single-pass classify: returns the class AND emits the parsed L3/L4 offsets so the
   caller's noise-refinement (IOC set + flow-cutoff) reuses them instead of re-parsing.
   `cand` is set when the packet is IPv4 TCP/UDP with valid ports (the only case the
   refinement cares about). Noise is ~94% of a big pipe, so dropping the second parse there
   is the hot-path win. */
/* classes: 0=DNS 1=DPI 2=noise 3=IOC-IP 4=HEAD(TLS/QUIC handshake) 5=SYN(TCP connect, heuristics).
   cand = IPv4 TCP/UDP with valid ports; ipv4 = any IPv4 packet (l3 valid) -> IOC works for ICMP too. */
struct mt_pktinfo { int cand; int ipv4; int proto; unsigned int l3; unsigned int l4; unsigned short sport, dport; };
static inline int mt_classify(const struct mt_classcfg* cfg, const unsigned char* p,
                              unsigned int len, struct mt_pktinfo* o)
{
  o->cand = 0;
  o->ipv4 = 0;
  unsigned int l2 = cfg->l2_off;
  /* Find the IPv4 header, transparently skipping up to two 802.1Q/802.1ad VLAN tags
     (TPID 0x8100 / 0x88a8 in the two bytes preceding the current offset). Validate IPv4 by
     the version nibble, which is datalink-agnostic (Ethernet / SLL / raw). */
  int vguard = 0;
  for (;;) {
    if (len < l2 + 20) return 2;                          /* need a full minimal IPv4 header */
    if ((p[l2] >> 4) == 4) break;                         /* IPv4 header located */
    if (vguard++ >= 2 || l2 < 2) return 2;
    if ((p[l2 - 2] == 0x81 && p[l2 - 1] == 0x00) || (p[l2 - 2] == 0x88 && p[l2 - 1] == 0xa8))
      l2 += 4;                                            /* skip one VLAN tag */
    else
      return 2;                                           /* not IPv4 and not a VLAN tag */
  }
  o->l3 = l2;
  o->ipv4 = 1;                                            /* IPv4 located -> IOC works for any proto */
  unsigned int ihl = (p[l2] & 0x0f) * 4;
  if (ihl < 20) return 2;                                 /* invalid IHL */
  unsigned int l4 = l2 + ihl;
  o->proto = p[l2 + 9];
  if (o->proto != 17 && o->proto != 6) return 2;          /* ICMP/other: noise, but ipv4 set for IOC */
  if (len < l4 + 4) return 2;
  int proto = o->proto;
  unsigned short sport = (p[l4] << 8) | p[l4 + 1];
  unsigned short dport = (p[l4 + 2] << 8) | p[l4 + 3];
  o->cand = 1; o->l4 = l4; o->sport = sport; o->dport = dport;
  if (sport == cfg->dns_port || dport == cfg->dns_port) return 0;   /* DNS */
  if (proto == 6 && len >= l4 + 14) {
    unsigned char flags = p[l4 + 13];
    if (flags == 0x02) return 5;                          /* pure SYN -> connection (scan/infection heuristics) */
    /* DPI: a payload-bearing TCP packet on a watched (HTTP) port. NOT gated on PSH, because
       Maltrail inspects HTTP requests AND responses (any segment carrying "HTTP/"), and a
       header-bearing segment is not always PSH. Bare ACKs (no payload) carry no HTTP and, if
       to/from a trail IP, are caught by the IOC class instead. */
    unsigned int tcphl = ((p[l4 + 12] >> 4) & 0x0f) * 4;
    if (tcphl >= 20 && len > l4 + tcphl) {                /* has TCP payload */
      for (unsigned i = 0; i < cfg->ndpi; i++)
        if (sport == cfg->dpi_ports[i] || dport == cfg->dpi_ports[i]) return 1;  /* DPI */
    }
  }
  return 2;                                                /* noise */
}
static inline int mt_is_tls_port(const struct mt_classcfg* cfg, unsigned short sport, unsigned short dport)
{
  for (unsigned i = 0; i < cfg->ntls; i++)
    if (sport == cfg->tls_ports[i] || dport == cfg->tls_ports[i]) return 1;
  return 0;
}

#include <stdlib.h>
#include <string.h>

/* tiny open-addressing uint32 IP set (network-order keys; 0.0.0.0 reserved as empty sentinel) */
struct mt_ipset { unsigned int* slots; unsigned int mask; };
static struct mt_ipset* ipset_build(const unsigned char* data, Py_ssize_t len)
{
  unsigned int n = (unsigned int)(len / 4), cap = 16;
  while (cap < n * 2 + 1) cap <<= 1;
  struct mt_ipset* s = (struct mt_ipset*)malloc(sizeof(*s));
  if (!s) return NULL;
  s->slots = (unsigned int*)calloc(cap, sizeof(unsigned int));
  if (!s->slots) { free(s); return NULL; }
  s->mask = cap - 1;
  for (unsigned int i = 0; i < n; i++) {
    unsigned int ip; memcpy(&ip, data + i * 4, 4);
    if (!ip) continue;
    unsigned int j = (ip * 2654435761u) & s->mask;
    while (s->slots[j] && s->slots[j] != ip) j = (j + 1) & s->mask;
    s->slots[j] = ip;
  }
  return s;
}
static inline int ipset_has(struct mt_ipset* s, unsigned int ip)
{
  if (!s || !ip) return 0;
  unsigned int j = (ip * 2654435761u) & s->mask;
  while (s->slots[j]) { if (s->slots[j] == ip) return 1; j = (j + 1) & s->mask; }
  return 0;
}
static void ipset_free(struct mt_ipset* s) { if (s) { free(s->slots); free(s); } }

/* approximate per-flow packet counter (overwrite-on-collision LRU); for flow-cutoff */
struct mt_flowtab { unsigned long long* keys; unsigned int* cnt; unsigned int mask; };
static struct mt_flowtab* flowtab_build(unsigned int bits)
{
  unsigned int cap = 1u << bits;
  struct mt_flowtab* f = (struct mt_flowtab*)malloc(sizeof(*f));
  if (!f) return NULL;
  f->keys = (unsigned long long*)calloc(cap, sizeof(unsigned long long));
  f->cnt  = (unsigned int*)calloc(cap, sizeof(unsigned int));
  if (!f->keys || !f->cnt) { free(f->keys); free(f->cnt); free(f); return NULL; }
  f->mask = cap - 1;
  return f;
}
static inline unsigned int flow_seen(struct mt_flowtab* f, unsigned long long key)
{
  unsigned int slot = (unsigned int)((key * 1099511628211ULL) >> 40) & f->mask;
  if (f->keys[slot] != key) { f->keys[slot] = key; f->cnt[slot] = 0; }   /* new flow / evicted */
  return f->cnt[slot]++;                                                  /* count before increment */
}
static void flowtab_free(struct mt_flowtab* f) { if (f) { free(f->keys); free(f->cnt); free(f); } }

/* Locate the IPv4 header, skipping up to two 802.1Q/802.1ad VLAN tags; return its offset or -1. */
static inline int locate_ipv4(unsigned int l2, const unsigned char* p, unsigned int len)
{
  int vguard = 0;
  for (;;) {
    if (len < l2 + 20) return -1;
    if ((p[l2] >> 4) == 4) return (int)l2;
    if (vguard++ >= 2 || l2 < 2) return -1;
    if ((p[l2 - 2] == 0x81 && p[l2 - 1] == 0x00) || (p[l2 - 2] == 0x88 && p[l2 - 1] == 0xa8))
      l2 += 4;
    else
      return -1;
  }
}

/* GENERIC profile (the default). Three classes, all of which are things a stateless BPF filter
   cannot express, so the method earns its place next to setfilter():
     0 OTHER      didn't match anything below
     1 FLOW_HEAD  within the first `flow_cutoff` packets of its flow (TCP or UDP) -- the start of a
                  connection, where the interesting bytes live (e.g. the TLS SNI). BPF has no flow state.
     2 SET_MATCH  src or dst address is in the caller-supplied address set (any size, any protocol). */
static inline int classify_generic(const struct mt_classcfg* cfg, struct mt_ipset* set,
                                   struct mt_flowtab* flowtab, unsigned int flow_cutoff,
                                   const unsigned char* p, unsigned int len)
{
  int l3 = locate_ipv4(cfg->l2_off, p, len);
  if (l3 < 0) return 0;                                       /* OTHER (not IPv4) */
  unsigned int sip, dip; memcpy(&sip, p + l3 + 12, 4); memcpy(&dip, p + l3 + 16, 4);
  if (set && (ipset_has(set, sip) || ipset_has(set, dip)))
    return 2;                                                 /* SET_MATCH */
  if (flowtab && flow_cutoff) {
    int proto = p[l3 + 9];
    if (proto == 6 || proto == 17) {                          /* flow key needs ports */
      unsigned int ihl = (p[l3] & 0x0f) * 4, l4 = l3 + ihl;
      if (ihl >= 20 && len >= l4 + 4) {
        unsigned short sp = (p[l4] << 8) | p[l4 + 1];
        unsigned short dp = (p[l4 + 2] << 8) | p[l4 + 3];
        unsigned long long key = ((unsigned long long)sip * 2654435761u)
                               ^ ((unsigned long long)dip * 40503u)
                               ^ (((unsigned long long)((sp << 16) | dp)) * 2246822519ull)
                               ^ (unsigned)proto;
        if (flow_seen(flowtab, key) < flow_cutoff) return 1;  /* FLOW_HEAD */
      }
    }
  }
  return 0;                                                   /* OTHER */
}

/* shared classify + noise-refinement (IOC set + flow-cutoff). Returns final class 0..4. */
static inline int classify_refine(const struct mt_classcfg* cfg, struct mt_ipset* ioc,
                                  struct mt_flowtab* flowtab, unsigned int flow_cutoff,
                                  const unsigned char* pkt, unsigned int caplen)
{
  struct mt_pktinfo pi;
  int cls = mt_classify(cfg, pkt, caplen, &pi);
  if (cls == 2 && pi.ipv4 && (ioc || flowtab)) {
    unsigned int l2 = pi.l3;   /* VLAN-resolved IPv4 header offset */
    unsigned int sip, dip; memcpy(&sip, pkt + l2 + 12, 4); memcpy(&dip, pkt + l2 + 16, 4);
    if (ioc && (ipset_has(ioc, sip) || ipset_has(ioc, dip)))
      cls = 3;                                             /* known-bad IP, ANY protocol incl ICMP */
    else if (pi.cand && flowtab && mt_is_tls_port(cfg, pi.sport, pi.dport)) {
      unsigned long long key = ((unsigned long long)sip * 2654435761u)
                             ^ ((unsigned long long)dip * 40503u)
                             ^ (((unsigned long long)((pi.sport << 16) | pi.dport)) * 2246822519ull)
                             ^ (unsigned)pi.proto;
      if (flow_seen(flowtab, key) < flow_cutoff) cls = 4;
    }
  }
  return cls;
}

/* Pick the classifier for the active profile. Returns a dense class INDEX (0-based) used for the
   admit mask and counters; the public class id delivered to the callback is profile_base()+index. */
static inline int classify_dispatch(const struct mt_classcfg* cfg, struct mt_ipset* set,
                                    struct mt_flowtab* flowtab, unsigned int flow_cutoff,
                                    const unsigned char* pkt, unsigned int caplen)
{
  if (cfg->profile == 1)
    return classify_refine(cfg, set, flowtab, flow_cutoff, pkt, caplen);  /* security: 0..5 */
  return classify_generic(cfg, set, flowtab, flow_cutoff, pkt, caplen);   /* generic: 0..2 */
}
/* security-profile class ids are offset by 100 so a general user's 0/1/2 never collide with them */
#define MT_PROFILE_BASE 100
static inline int profile_base(const struct mt_classcfg* cfg) { return cfg->profile == 1 ? MT_PROFILE_BASE : 0; }

struct FilteredContext {
  pcap_t* ppcap_t;
  PyObject* pyfunc;
  PyThreadState* thread_state;
  int admit_mask;
  struct mt_ipset* ioc;
  struct mt_flowtab* flowtab;
  unsigned int flow_cutoff;
  struct mt_classcfg cfg;
  unsigned long long* live;   /* -> pcapobject.filt_counts: [0]adm [1]drop [2..7]=class index 0..5 */
};

static void
FilteredCallBack(u_char* user, const struct pcap_pkthdr* header, const u_char* packetdata)
{
  FilteredContext* c = (FilteredContext*)user;
  int idx = classify_dispatch(&c->cfg, c->ioc, c->flowtab, c->flow_cutoff, packetdata, header->caplen);
  c->live[2 + idx]++;
  if (!((c->admit_mask >> idx) & 1)) { c->live[1]++; return; }   /* dropped in C, no GIL, no Python */
  c->live[0]++;
  int cls = profile_base(&c->cfg) + idx;                         /* public class id for the callback */
  Py_ssize_t caplen = header->caplen;
  PyEval_RestoreThread(c->thread_state);
  PyObject* hdr = new_pcap_pkthdr(header);
#if PY_MAJOR_VERSION >= 3
  PyObject* arglist = Py_BuildValue("Oy#i", hdr, packetdata, caplen, cls);
#else
  PyObject* arglist = Py_BuildValue("Os#i", hdr, packetdata, caplen, cls);
#endif
  PyObject* result = PyObject_CallObject(c->pyfunc, arglist);
  Py_XDECREF(arglist);
  if (result) Py_DECREF(result);
  Py_DECREF(hdr);
  if (!result) pcap_breakloop(c->ppcap_t);
  c->thread_state = PyEval_SaveThread();
}

/* Convert a Python sequence of ints into a malloc'd uint16 port array.
   Returns the array (caller frees) and sets *outn; on None/empty returns NULL with *outn=0.
   On a type error returns NULL and sets *err=1. */
static unsigned short* seq_to_ports(PyObject* seq, unsigned int* outn, int* err)
{
  *outn = 0; *err = 0;
  if (!seq || seq == Py_None) return NULL;
  PyObject* fast = PySequence_Fast(seq, "ports must be a sequence of ints");
  if (!fast) { *err = 1; return NULL; }
  Py_ssize_t n = PySequence_Fast_GET_SIZE(fast);
  if (n <= 0) { Py_DECREF(fast); return NULL; }
  unsigned short* ports = (unsigned short*)malloc((size_t)n * sizeof(unsigned short));
  if (!ports) { Py_DECREF(fast); PyErr_NoMemory(); *err = 1; return NULL; }
  for (Py_ssize_t i = 0; i < n; i++) {
    long v = PyLong_AsLong(PySequence_Fast_GET_ITEM(fast, i));
    if (v == -1 && PyErr_Occurred()) { free(ports); Py_DECREF(fast); *err = 1; return NULL; }
    ports[i] = (unsigned short)(v & 0xffff);
  }
  Py_DECREF(fast);
  *outn = (unsigned int)n;
  return ports;
}

static PyObject*
p_loop_filtered(pcapobject* pp, PyObject* args)
{
  int cant, admit_mask = 7;    /* generic default: admit OTHER(0)+FLOW_HEAD(1)+SET_MATCH(2) */
  int flow_cutoff = 0;
  int dns_port = 53;
  int l2_offset = 14;          /* Ethernet default; LINUX_SLL=16, DLT_RAW/null=0 */
  int profile = 0;             /* 0 = generic; 1 = security (DNS/HTTP/IP-set/handshake/SYN at 100+) */
  PyObject* PyFunc;
  PyObject* dpi_seq = NULL; PyObject* tls_seq = NULL;
  const char* iocbuf = NULL; Py_ssize_t ioclen = 0;
  if (Py_TYPE(pp) != &Pcaptype) { PyErr_SetString(PcapError, "Not a pcap object"); return NULL; }
  if (!pp->pcap) return err_closed();
#if PY_MAJOR_VERSION >= 3
  if (!PyArg_ParseTuple(args, "iO|iy#iOOiii:loop_filtered", &cant, &PyFunc, &admit_mask, &iocbuf, &ioclen, &flow_cutoff, &dpi_seq, &tls_seq, &dns_port, &l2_offset, &profile)) return NULL;
#else
  if (!PyArg_ParseTuple(args, "iO|is#iOOiii:loop_filtered", &cant, &PyFunc, &admit_mask, &iocbuf, &ioclen, &flow_cutoff, &dpi_seq, &tls_seq, &dns_port, &l2_offset, &profile)) return NULL;
#endif
  if (l2_offset < 0 || l2_offset > 64) { PyErr_SetString(PyExc_ValueError, "l2_offset out of range [0,64]"); return NULL; }
  if (profile != 0 && profile != 1) { PyErr_SetString(PyExc_ValueError, "profile must be 0 (generic) or 1 (security)"); return NULL; }

  int perr = 0;
  unsigned int ndpi = 0, ntls = 0;
  unsigned short* dpi_ports = seq_to_ports(dpi_seq, &ndpi, &perr);
  if (perr) { free(dpi_ports); return NULL; }
  unsigned short* tls_ports = seq_to_ports(tls_seq, &ntls, &perr);
  if (perr) { free(dpi_ports); free(tls_ports); return NULL; }

  /* None/absent -> built-in defaults; an explicitly provided sequence (even empty) is honored */
  int dpi_given = (dpi_seq && dpi_seq != Py_None);
  int tls_given = (tls_seq && tls_seq != Py_None);
  FilteredContext c;
  c.ppcap_t = pp->pcap; c.pyfunc = PyFunc; c.admit_mask = admit_mask;
  c.cfg.dns_port = (unsigned short)dns_port;
  c.cfg.dpi_ports = dpi_given ? dpi_ports : MT_DPI_PORTS_DEFAULT;
  c.cfg.ndpi = dpi_given ? ndpi : (unsigned)(sizeof(MT_DPI_PORTS_DEFAULT)/sizeof(MT_DPI_PORTS_DEFAULT[0]));
  c.cfg.tls_ports = tls_given ? tls_ports : MT_TLS_PORTS_DEFAULT;
  c.cfg.ntls = tls_given ? ntls : (unsigned)(sizeof(MT_TLS_PORTS_DEFAULT)/sizeof(MT_TLS_PORTS_DEFAULT[0]));
  c.cfg.l2_off = (unsigned)l2_offset;
  c.cfg.profile = profile;
  c.ioc = (iocbuf && ioclen >= 4) ? ipset_build((const unsigned char*)iocbuf, ioclen) : NULL;
  c.flow_cutoff = (flow_cutoff > 0) ? (unsigned)flow_cutoff : 0;
  c.flowtab = c.flow_cutoff ? flowtab_build(20) : NULL;   /* 1M slots ~12MB */
  c.live = pp->filt_counts;
  for (int i = 0; i < 8; i++) pp->filt_counts[i] = 0;     /* reset for this run; pollable mid-loop */
  pp->filt_profile = profile;
  c.thread_state = PyEval_SaveThread();
  int ret = pcap_loop(pp->pcap, cant, FilteredCallBack, (u_char*)&c);
  PyEval_RestoreThread(c.thread_state);
  ipset_free(c.ioc);
  flowtab_free(c.flowtab);
  free(dpi_ports);
  free(tls_ports);

  if (PyErr_Occurred()) return NULL;
  if (ret < 0) {
    if (ret != -2) PyErr_SetString(PcapError, pcap_geterr(pp->pcap));
    return NULL;
  }
  unsigned long long* s = pp->filt_counts;
  /* generic -> (admitted, dropped, other, flow_head, set_match);
     security -> (admitted, dropped, dns, http, noise, ipset, handshake, syn) */
  if (profile == 1)
    return Py_BuildValue("(KKKKKKKK)", s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7]);
  return Py_BuildValue("(KKKKK)", s[0], s[1], s[2], s[3], s[4]);
}

/* F5: read the live per-class counters of an in-flight (or finished) loop_filtered.
   Safe to call from another Python thread while loop_filtered runs (counters are
   monotonic; a torn read is harmless for stats). Returns (admitted,dropped,dns,dpi,noise,ioc,head). */
static PyObject*
p_filtered_stats(pcapobject* pp, PyObject*)
{
  if (Py_TYPE(pp) != &Pcaptype) { PyErr_SetString(PcapError, "Not a pcap object"); return NULL; }
  unsigned long long* s = pp->filt_counts;
  if (pp->filt_profile == 1)
    return Py_BuildValue("(KKKKKKKK)", s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7]);
  return Py_BuildValue("(KKKKK)", s[0], s[1], s[2], s[3], s[4]);
}

/* ---- F2 (producer half): classify+admit and write admitted packets straight into a
   caller-provided writable buffer (the shared-memory ring's backing store), with ZERO
   per-packet Python crossing. Proves the producer can feed a ring at full C speed (GIL
   fully released for the whole loop); worker processes drain the ring in parallel.
   Slot layout per admitted packet: [u32 caplen-LE][u8 cls][caplen bytes]. Stops writing
   when the buffer is full (overflow counted) but keeps classifying so stats stay exact. */
struct BufferCtx {
  unsigned char* buf; size_t cap, used;
  int admit_mask;
  struct mt_ipset* ioc; struct mt_flowtab* flowtab; unsigned int flow_cutoff;
  struct mt_classcfg cfg;
  unsigned long long written, dropped, overflow, cls[6];
};
static void
BufferCallBack(u_char* user, const struct pcap_pkthdr* h, const u_char* pkt)
{
  struct BufferCtx* b = (struct BufferCtx*)user;
  int idx = classify_dispatch(&b->cfg, b->ioc, b->flowtab, b->flow_cutoff, pkt, h->caplen);
  b->cls[idx]++;
  if (!((b->admit_mask >> idx) & 1)) { b->dropped++; return; }
  unsigned int cl = h->caplen;
  size_t need = 5 + cl;
  if (b->used + need > b->cap) { b->overflow++; return; }   /* ring backing full; consumer behind */
  unsigned char* p = b->buf + b->used;
  p[0] = cl & 0xff; p[1] = (cl >> 8) & 0xff; p[2] = (cl >> 16) & 0xff; p[3] = (cl >> 24) & 0xff;
  p[4] = (unsigned char)(profile_base(&b->cfg) + idx);   /* public class id in the ring */
  memcpy(p + 5, pkt, cl);
  b->used += need;
  b->written++;
}

static PyObject*
p_loop_to_buffer(pcapobject* pp, PyObject* args)
{
  int cant, admit_mask = 7, flow_cutoff = 0, dns_port = 53, l2_offset = 14, profile = 0;
  Py_buffer view;
  PyObject* dpi_seq = NULL; PyObject* tls_seq = NULL;
  const char* iocbuf = NULL; Py_ssize_t ioclen = 0;
  if (Py_TYPE(pp) != &Pcaptype) { PyErr_SetString(PcapError, "Not a pcap object"); return NULL; }
  if (!pp->pcap) return err_closed();
#if PY_MAJOR_VERSION >= 3
  if (!PyArg_ParseTuple(args, "iw*|iy#iOOiii:loop_to_buffer", &cant, &view, &admit_mask, &iocbuf, &ioclen, &flow_cutoff, &dpi_seq, &tls_seq, &dns_port, &l2_offset, &profile)) return NULL;
#else
  if (!PyArg_ParseTuple(args, "iw*|is#iOOiii:loop_to_buffer", &cant, &view, &admit_mask, &iocbuf, &ioclen, &flow_cutoff, &dpi_seq, &tls_seq, &dns_port, &l2_offset, &profile)) return NULL;
#endif
  if (l2_offset < 0 || l2_offset > 64) { PyBuffer_Release(&view); PyErr_SetString(PyExc_ValueError, "l2_offset out of range [0,64]"); return NULL; }
  if (profile != 0 && profile != 1) { PyBuffer_Release(&view); PyErr_SetString(PyExc_ValueError, "profile must be 0 or 1"); return NULL; }

  int perr = 0; unsigned int ndpi = 0, ntls = 0;
  unsigned short* dpi_ports = seq_to_ports(dpi_seq, &ndpi, &perr);
  if (perr) { PyBuffer_Release(&view); free(dpi_ports); return NULL; }
  unsigned short* tls_ports = seq_to_ports(tls_seq, &ntls, &perr);
  if (perr) { PyBuffer_Release(&view); free(dpi_ports); free(tls_ports); return NULL; }

  int dpi_given = (dpi_seq && dpi_seq != Py_None);
  int tls_given = (tls_seq && tls_seq != Py_None);
  struct BufferCtx b;
  b.buf = (unsigned char*)view.buf; b.cap = (size_t)view.len; b.used = 0;
  b.admit_mask = admit_mask;
  b.cfg.dns_port = (unsigned short)dns_port;
  b.cfg.dpi_ports = dpi_given ? dpi_ports : MT_DPI_PORTS_DEFAULT;
  b.cfg.ndpi = dpi_given ? ndpi : (unsigned)(sizeof(MT_DPI_PORTS_DEFAULT)/sizeof(MT_DPI_PORTS_DEFAULT[0]));
  b.cfg.tls_ports = tls_given ? tls_ports : MT_TLS_PORTS_DEFAULT;
  b.cfg.ntls = tls_given ? ntls : (unsigned)(sizeof(MT_TLS_PORTS_DEFAULT)/sizeof(MT_TLS_PORTS_DEFAULT[0]));
  b.cfg.l2_off = (unsigned)l2_offset;
  b.cfg.profile = profile;
  b.ioc = (iocbuf && ioclen >= 4) ? ipset_build((const unsigned char*)iocbuf, ioclen) : NULL;
  b.flow_cutoff = (flow_cutoff > 0) ? (unsigned)flow_cutoff : 0;
  b.flowtab = b.flow_cutoff ? flowtab_build(20) : NULL;
  b.written = b.dropped = b.overflow = b.cls[0] = b.cls[1] = b.cls[2] = b.cls[3] = b.cls[4] = b.cls[5] = 0;

  Py_BEGIN_ALLOW_THREADS                       /* GIL released for the ENTIRE loop — no per-pkt crossing */
  pcap_loop(pp->pcap, cant, BufferCallBack, (u_char*)&b);
  Py_END_ALLOW_THREADS

  ipset_free(b.ioc); flowtab_free(b.flowtab); free(dpi_ports); free(tls_ports);
  PyBuffer_Release(&view);
  /* generic -> 7-tuple (written,dropped,overflow,used, other,flow_head,set_match);
     security -> 10-tuple (... + the 6 security class counts) */
  if (profile == 1)
    return Py_BuildValue("(KKKKKKKKKK)", b.written, b.dropped, b.overflow, (unsigned long long)b.used,
                         b.cls[0], b.cls[1], b.cls[2], b.cls[3], b.cls[4], b.cls[5]);
  return Py_BuildValue("(KKKKKKK)", b.written, b.dropped, b.overflow, (unsigned long long)b.used,
                       b.cls[0], b.cls[1], b.cls[2]);
}

/* ---- F1: batched delivery — N packets per call (one buffer + index), amortize the boundary ---- */
struct BatchMeta { unsigned int sec, usec, off, len; };
struct BatchCtx { unsigned char* buf; size_t cap, used; struct BatchMeta* meta; unsigned int mcap, n; };

static void
BatchCallBack(u_char* user, const struct pcap_pkthdr* h, const u_char* data)
{
  struct BatchCtx* b = (struct BatchCtx*)user;
  unsigned int cl = h->caplen;
  if (b->used + cl > b->cap) {
    size_t nc = b->cap * 2; if (nc < b->used + cl + 4096) nc = b->used + cl + 4096;
    unsigned char* nb = (unsigned char*)realloc(b->buf, nc); if (!nb) return; b->buf = nb; b->cap = nc;
  }
  if (b->n >= b->mcap) {
    unsigned int nm = b->mcap * 2; if (nm == 0) nm = 256;
    struct BatchMeta* nmeta = (struct BatchMeta*)realloc(b->meta, nm * sizeof(struct BatchMeta));
    if (!nmeta) return; b->meta = nmeta; b->mcap = nm;
  }
  memcpy(b->buf + b->used, data, cl);
  b->meta[b->n].sec = (unsigned int)h->ts.tv_sec; b->meta[b->n].usec = (unsigned int)h->ts.tv_usec;
  b->meta[b->n].off = (unsigned int)b->used;      b->meta[b->n].len = cl;
  b->used += cl; b->n++;
}

static PyObject*
p_next_batch(pcapobject* pp, PyObject* args)
{
  int max_n = 256;
  if (Py_TYPE(pp) != &Pcaptype) { PyErr_SetString(PcapError, "Not a pcap object"); return NULL; }
  if (!pp->pcap) return err_closed();
  if (!PyArg_ParseTuple(args, "i:next_batch", &max_n)) return NULL;
  if (max_n <= 0) max_n = 256;

  struct BatchCtx b;
  b.cap = 65536; b.used = 0; b.mcap = (unsigned)max_n; b.n = 0;
  b.buf = (unsigned char*)malloc(b.cap);
  b.meta = (struct BatchMeta*)malloc(b.mcap * sizeof(struct BatchMeta));
  if (!b.buf || !b.meta) { free(b.buf); free(b.meta); return PyErr_NoMemory(); }

  PyThreadState* ts = PyEval_SaveThread();
  int ret = pcap_dispatch(pp->pcap, max_n, BatchCallBack, (u_char*)&b);
  PyEval_RestoreThread(ts);

  if (ret < 0 && ret != -2) {
    free(b.buf); free(b.meta);
    PyErr_SetString(PcapError, pcap_geterr(pp->pcap));
    return NULL;
  }

  /* packed meta: N contiguous 16-byte records (sec,usec,off,len as native uint32) -> ONE bytes,
     no per-packet Python object. Consumer reads via array('I')/struct (records = len(meta)//16). */
  PyObject* pybuf  = PyBytes_FromStringAndSize((const char*)b.buf,  (Py_ssize_t)b.used);
  PyObject* pymeta = PyBytes_FromStringAndSize((const char*)b.meta, (Py_ssize_t)(b.n * sizeof(struct BatchMeta)));
  free(b.buf); free(b.meta);
  if (!pybuf || !pymeta) { Py_XDECREF(pybuf); Py_XDECREF(pymeta); return PyErr_NoMemory(); }
  return Py_BuildValue("(NN)", pybuf, pymeta);
}
