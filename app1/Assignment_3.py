from Assignment_3_Helper import *
import pysvf

class Assignment3(AbstractExecution):
    def __init__(self, pag: pysvf.SVFIR) -> None:
        super().__init__(pag)
        self.func_map: Dict[str, Callable[[pysvf.CallICFGNode], None]] = {}
        self.init_ext_fun_map()

    def init_ext_fun_map(self):
        # svf_assert
        def sse_svf_assert(call_node: pysvf.CallICFGNode):
            as_ = self.post_abs_trace[call_node]
            arg0 = call_node.getArgument(0).getId()
            if as_[arg0].getInterval().equals(IntervalValue(1, 1)):
                print("The assertion is successfully verified!!")
            else:
                raise AssertionError(f"Assertion failure: {call_node.toString()}")
        self.func_map["svf_assert"] = sse_svf_assert

        # svf_assert_eq
        def sse_svf_assert_eq(call_node: pysvf.CallICFGNode):
            as_ = self.post_abs_trace[call_node]
            a0 = call_node.getArgument(0).getId()
            a1 = call_node.getArgument(1).getId()
            if as_[a0].getInterval().equals(as_[a1].getInterval()):
                print("The assertion is successfully verified!!")
            else:
                raise AssertionError(f"Assertion failure: {call_node.toString()}")
        self.func_map["svf_assert_eq"] = sse_svf_assert_eq

        # recv
        def sse_recv(call_node: pysvf.CallICFGNode):
            as_ = self.post_abs_trace[call_node]
            len_id = call_node.getArgument(2).getId()
            length = as_[len_id].getInterval()
            lhs_id = call_node.getRetICFGNode().getActualRet().getId()
            as_[lhs_id] = length - IntervalValue(1, 1)
        self.func_map["recv"] = sse_recv
        self.func_map["__recv"] = sse_recv


        # free 家族
        def sse_free(call_node: pysvf.CallICFGNode):
            as_ = self.post_abs_trace[call_node]
            ptr_id = call_node.getArgument(0).getId()
            for addr in as_[ptr_id].getAddrs():
                if not AbstractState.isInvalidMem(addr):
                    as_.addToFreedAddrs(addr)
        self.func_map["free"] = sse_free
        self.func_map["cfree"] = sse_free
        self.func_map["VOS_MemFree"] = sse_free
        self.func_map["safe_free"] = sse_free
        self.func_map["xfree"] = sse_free

        # malloc 家族
        def sse_malloc(call_node: pysvf.CallICFGNode):
            as_ = self.post_abs_trace[call_node]
            ptr_id = call_node.getRetICFGNode().getActualRet().getId()
            as_[ptr_id] = AbstractValue(IntervalValue.top())
        self.func_map["malloc"] = sse_malloc

        import math
        
        def register_unary(names, impl):
            # names: 同一个实现绑定多个别名（如 ["sin", "llvm.sin.f64"]）
            def handler(call_node):
                as_ = self.post_abs_trace[call_node]
                rhs_id = call_node.getArgument(0).getId()
                if not as_.inVarToValTable(rhs_id):
                    return
                rhs = as_[rhs_id].getInterval().lb().getIntNumeral()
                res = impl(rhs)
                lhs_id = call_node.getRetICFGNode().getActualRet().getId()
                as_[lhs_id] = AbstractValue(IntervalValue(res))
            for n in names:
                self.func_map[n] = handler

        # ctype 近似：unsigned char 语义
        def _uc(x): 
            return x & 0xFF
        def _ch(x):
            try:
                return chr(_uc(x))
            except ValueError:
                return '\x00'

        spec = [
            # 字符类（返回 0/1）
            (["isalnum"],          lambda x: int(_ch(x).isalnum())),
            (["isalpha"],          lambda x: int(_ch(x).isalpha())),
            (["isblank"],          lambda x: int(_ch(x) in ('\t', ' '))),
            (["iscntrl"],          lambda x: int(ord(_ch(x)) < 32 or ord(_ch(x)) == 127)),
            (["isdigit"],          lambda x: int(_ch(x).isdigit())),
            (["isgraph"],          lambda x: int(33 <= ord(_ch(x)) <= 126)),
            (["isprint"],          lambda x: int(32 <= ord(_ch(x)) <= 126)),
            (["ispunct"],          lambda x: int((not _ch(x).isalnum()) and (not _ch(x).isspace()) and 32 <= ord(_ch(x)) <= 126)),
            (["isspace"],          lambda x: int(_ch(x).isspace())),
            (["isupper"],          lambda x: int(_ch(x).isupper())),
            (["isxdigit"],         lambda x: int(_ch(x) in "0123456789abcdefABCDEF")),

            # 数学函数（同时绑定 LLVM 名称）
            (["sin",  "llvm.sin.f64"],  lambda x: math.sin(float(x))),
            (["cos",  "llvm.cos.f64"],  lambda x: math.cos(float(x))),
            (["tan",  "llvm.tan.f64"],  lambda x: math.tan(float(x))),
            (["log",  "llvm.log.f64"],  lambda x: math.log(max(float(x), 1e-300))),  # 避免 -inf/NaN
            (["sinh"],                    lambda x: math.sinh(float(x))),
            (["cosh"],                    lambda x: math.cosh(float(x))),
            (["tanh"],                    lambda x: math.tanh(float(x))),
        ]

        for names, impl in spec:
            register_unary(names, impl)     
        # map string helpers
        self.func_map["strlen"] = self._sse_strlen
        self.func_map["strcpy"] = self._handle_strcpy
        self.func_map["strcat"] = self._handle_strcat
        # buffer overflow check rules for external APIs
        self.ext_api_buf_rules = {
            # memcpy/memmove family: (buffer_idx, size_idx)
            "llvm.memcpy.p0.p0.i64": [(0, 2), (1, 2)],
            "llvm.memmove.p0.p0.i64": [(0, 2), (1, 2)],
            "__memcpy_chk": [(0, 2), (1, 2)],
            "memcpy": [(0, 2), (1, 2)],
            "memmove": [(0, 2), (1, 2)],
            "bcopy": [(0, 2), (1, 2)],
            "memccpy": [(0, 3), (1, 3)],
            # memset family
            "llvm.memset.p0.i64": [(0, 2)],
            "__memset_chk": [(0, 2)],
            "wmemset": [(0, 2)],
            # strncpy-ish
            "strncpy": [(0, 2), (1, 2)],
            # iconv example (dst/src with their own sizes)
            "iconv": [(1, 2), (3, 4)],
        }
        # memset
        def sse_memset(call):
            as_ = self.post_abs_trace[call]
            dst = call.getArgument(0)
            elem = as_[call.getArgument(1).getId()].getInterval()
            length = as_[call.getArgument(2).getId()].getInterval()
            self._handle_memset(as_, dst, elem, length)
        self.func_map["llvm.memset.p0.i64"] = sse_memset

        # memcpy
        def sse_memcpy(call):
            as_ = self.post_abs_trace[call]
            dst = call.getArgument(0)
            src = call.getArgument(1)
            length = as_[call.getArgument(2).getId()].getInterval()
            self._handle_memcpy(as_, dst, src, length, 0)
        self.func_map["llvm.memcpy.p0.p0.i64"] = sse_memcpy

        # strcmp / strncmp：保守设为 [-1,1]；可判同参/零长度返回 0
        def sse_strcmp(call):
            as_ = self.post_abs_trace[call]
            a0 = call.getArgument(0).getId()
            a1 = call.getArgument(1).getId()
            lhs = call.getRetICFGNode().getActualRet().getId()
            if a0 == a1:
                as_[lhs] = IntervalValue(0, 0)
            else:
                as_[lhs] = IntervalValue(-1, 1)
        self.func_map["strcmp"] = sse_strcmp

        def sse_strncmp(call):
            as_ = self.post_abs_trace[call]
            a0 = call.getArgument(0).getId()
            a1 = call.getArgument(1).getId()
            n  = as_[call.getArgument(2).getId()].getInterval()
            lhs = call.getRetICFGNode().getActualRet().getId()
            if a0 == a1 or (n.is_numeral() and n.getIntNumeral() == 0):
                as_[lhs] = AbstractValue(IntervalValue(0, 0))
            else:
                as_[lhs] = AbstractValue(IntervalValue(-1, 1))
        self.func_map["strncmp"] = sse_strncmp

        # sprintf：保守处理 -> 返回打印长度 [0, MaxFieldLimit]
        def sse_sprintf(call):
            as_ = self.post_abs_trace[call]
            ret = call.getRetICFGNode().getActualRet()
            if ret:
                as_[ret.getId()] = AbstractValue(IntervalValue(0, pysvf.Options.max_field_limit()))
        self.func_map["sprintf"] = sse_sprintf

        # __isoc99_sscanf：复用 scanf 语义（若你有 self._sse_scanf）
        # 若尚未实现，可用你之前的 fscanf/scanf 逻辑替代
        if hasattr(self, "_sse_scanf"):
            self.func_map["__isoc99_sscanf"] = self._sse_scanf  

    def getFunctionWto(self, fun: pysvf.FunObjVar) -> str:
        wto = self.func_to_wto[fun]
        assert wto is not None and isinstance(wto, ICFGWTO)
        res = ""
        branch_edges = []
        queue = []
        queue.extend(wto.components)
        while queue:
            comp = queue.pop(0)
            if isinstance(comp, ICFGWTONode):
                res += str(comp.node.getId()) + " "
                # if node has branch stmt
                for stmt in comp.node.getSVFStmts():
                    if isinstance(stmt, pysvf.BranchStmt):
                        # append edge to branch_edges
                        for edge2 in comp.node.getOutEdges():
                            branch_edges.append(edge2)

                # if node has more than 1 in edges (merge node)
                if len(comp.node.getInEdges()) > 1:
                    # append edge to branch_edges
                    for edge2 in comp.node.getInEdges():
                        if isinstance(edge2.getSrcNode(), pysvf.IntraICFGNode):
                            branch_edges.append(edge2)

                
            elif isinstance(comp, ICFGWTOCycle):
                res += str(comp.head.node.getId()) + " "
                # queue insert to the front
                queue.insert(0, ")")
                for component in reversed(comp.components):
                    queue.insert(0, component)
                queue.insert(0, comp.head)
                queue.insert(0, "(")
            elif isinstance(comp, str):
                res += comp
        branch_edge_str = " ".join([str(edge.getSrcNode().getId()) + "->" + str(edge.getDstNode().getId()) for edge in branch_edges])
        return res + " " + branch_edge_str


    def hasPostTrace(self, node) -> bool:
        if isinstance(node, pysvf.ICFGNode):
            return node in self.post_abs_trace
        elif isinstance(node, int):
            node = self.svfir.getICFG().getGNode(node)
            return node in self.post_abs_trace
        else:
            assert False, f"Invalid node type: {type(node)}"

    #TODO : Implement the state updates for Copy, Binary, Store, Load, Gep, Phi
    # TODO: your code starts from here
    def updateStateOnGep(self, gep: pysvf.GepStmt):
        node = gep.getICFGNode()
        abstract_state = self.post_abs_trace[node]
        assert isinstance(abstract_state, AbstractState)
        lhs = gep.getLHSVarID()
        rhs = gep.getRHSVarID()
        if abstract_state.getVar(rhs).isAddr():
            offset = abstract_state.getElementIndex(gep)
            abstract_state[lhs] = abstract_state.getGepObjAddrs(rhs, offset)

    #TODO: your code starts from here
    def updateStateOnStore(self, store: pysvf.StoreStmt):
        node = store.getICFGNode()
        abstract_state = self.post_abs_trace[node]
        assert isinstance(abstract_state, AbstractState)
        lhs = store.getLHSVarID()
        rhs = store.getRHSVarID()
        if abstract_state.getVar(lhs).isAddr():
            abstract_state.storeValue(lhs, abstract_state[rhs])

    #TODO: your code starts from here
    # Find the comparison predicates in "class BinaryOPStmt:OpCode" under SVF/svf/include/SVFIR/SVFStatements.h
    # You are required to handle predicates (The program is assumed to have signed ints and also interger-overflow-free),
    # including Add, FAdd, Sub, FSub, Mul, FMul, SDiv, FDiv, UDiv, SRem, FRem, URem, Xor, And, Or, AShr, Shl, LShr
    def updateStateOnBinary(self, binary: pysvf.BinaryOPStmt):
        node = binary.getICFGNode()
        abstract_state = self.post_abs_trace[node]
        lhs = binary.getResId()
        op1 = binary.getOpVar(0)
        op2 = binary.getOpVar(1)
        
        # if op1 or op2 is not an interval, return
        if not abstract_state.getVar(op1.getId()).isInterval() or not abstract_state.getVar(op2.getId()).isInterval():
            abstract_state[lhs] = AbstractValue(IntervalValue.top())
            return
        assert abstract_state.getVar(op1.getId()).isInterval() and abstract_state.getVar(op2.getId()).isInterval()
        result = IntervalValue(0)
        val1 = abstract_state[op1.getId()].getInterval()
        val2 = abstract_state[op2.getId()].getInterval()
        assert(isinstance(val1, IntervalValue) and isinstance(val2, IntervalValue))
        if binary.getOpcode() == OpCode.Add or binary.getOpcode() == OpCode.FAdd:
            result = val1 + val2
        elif binary.getOpcode() == OpCode.Sub or binary.getOpcode() == OpCode.FSub:
            result = val1 - val2
        elif binary.getOpcode() == OpCode.Mul or binary.getOpcode() == OpCode.FMul:
            result = val1 * val2
        elif binary.getOpcode() == OpCode.UDiv or binary.getOpcode() == OpCode.SDiv or binary.getOpcode() == OpCode.FDiv:
            if int(val2.ub())>=0 and int(val2.lb()) <= 0:
                result = IntervalValue.top()
            else:
                result = val1 / val2
        elif binary.getOpcode() == OpCode.SRem or binary.getOpcode() == OpCode.FRem or binary.getOpcode() == OpCode.URem:
            if int(val2.ub())>=0 and int(val2.lb()) <= 0:
                result = IntervalValue.top()
            else:
                result = val1 % val2
        elif binary.getOpcode() == OpCode.Xor:
            result = val1 ^ val2
        elif binary.getOpcode() == OpCode.Or:
            result = val1 | val2
        elif binary.getOpcode() == OpCode.And:
            result = val1 & val2
        elif binary.getOpcode() == OpCode.Shl:
            result = val1 << val2
        elif binary.getOpcode() == OpCode.LShr or binary.getOpcode() == OpCode.AShr:
            result = val1 >> val2
        else:
            result = IntervalValue.top()
        abstract_state[lhs] = AbstractValue(result)


    #TODO: your code starts from here
    def updateStateOnLoad(self, load: pysvf.LoadStmt):
        node = load.getICFGNode()
        abstract_state = self.post_abs_trace[node]
        assert isinstance(abstract_state, AbstractState)
        lhs = load.getLHSVarID()
        rhs = load.getRHSVarID()
        if abstract_state.getVar(rhs).isAddr():
            abstract_state[lhs] = abstract_state.loadValue(rhs)
        else:
            abstract_state[lhs] = AbstractValue(IntervalValue.top())

    #TODO: your code starts from here
    def updateStateOnCopy(self, copy: pysvf.CopyStmt):
        node = copy.getICFGNode()
        abstract_state = self.post_abs_trace[node]
        # if "ptrtoint" in copy.toString():
        #     addrs = abstract_state[copy.getRHSVarID()].getAddrs()
        #     tmp = IntervalValue.bottom()
        #     for addr in addrs:
        #         tmp.join_with(IntervalValue(addr))
        #     if tmp == IntervalValue.bottom():
        #         tmp = IntervalValue.top()
        #     abstract_state[copy.getLHSVarID()] = tmp
        #     return
        abstract_state[copy.getLHSVarID()] = abstract_state[copy.getRHSVarID()]

    # TODO: your code starts from here
    def updateStateOnPhi(self, phi: pysvf.PhiStmt):
        node = phi.getICFGNode()
        abstract_state = self.post_abs_trace[node]
        lhs = phi.getResId()
        result = AbstractValue()
        for i in range(phi.getOpVarNum()):
            op_var = phi.getOpVar(i)
            if abstract_state.getVar(op_var.getId()).isInterval() or abstract_state.getVar(op_var.getId()).isAddr():
                result.join_with(abstract_state[op_var.getId()])
        abstract_state[lhs] = result

    """
    Detect buffer overflows in the given statement.

    TODO: handle GepStmt `lhs = rhs + off` and detect buffer overflow
    Step 1: For each `obj \in pts(rhs)`, get the size of allocated baseobj (entire mem object) via `obj_size = svfir->getBaseObj(objId)->getByteSizeOfObj();`
    There is a buffer overflow if `accessOffset.ub() >= obj_size`, where accessOffset is obtained via `getAccessOffset`
    Step 2: invoke `reportBufOverflow` with the current ICFGNode if an overflow is detected

    :param stmt: The statement to analyze for buffer overflows.
    :type stmt: pysvf.SVFStmt
    """
    def bufOverflowDetection(self, stmt: pysvf.SVFStmt):
        
        if isinstance(stmt, pysvf.GepStmt):
            abstract_state = self.post_abs_trace[stmt.getICFGNode()]
            lhs = stmt.getLHSVarID()
            rhs = stmt.getRHSVarID()

            # Update GEP object offset from base
            self.buf_overflow_helper.updateGepObjOffsetFromBase(abstract_state,
                abstract_state[lhs].getAddrs(),  abstract_state[rhs].getAddrs(),
                abstract_state.getByteOffset(stmt)
            )

            # TODO: your code starts from here
            # Check for buffer overflow
            for addr in abstract_state[rhs].getAddrs():
                obj_id = abstract_state.getIDFromAddr(addr)
                obj_size = self.svfir.getBaseObject(obj_id).getByteSizeOfObj()
                access_offset = self.getAccessOffset(obj_id, stmt)
                assert(isinstance(access_offset, pysvf.IntervalValue))

                if int(access_offset.ub()) >= obj_size:
                    msg = "Buffer overflow detected. Objsize: {}, but try to access offset {}".format(obj_size, access_offset)
                    self.buf_overflow_helper.reportBufOverflow(stmt.getICFGNode(), msg)

    """
    Handle external function calls and update the abstract state.

    This function processes specific external function calls, such as `mem_insert` and `str_insert`,
    to ensure that buffer overflows are detected and prevented. It checks the constraints on the
    buffer size and access offsets based on the function arguments.

    TODO: Steps:
    1. For `mem_insert`:
       - Validate that the buffer size is greater than or equal to the sum of the position and data size.
    2. For `str_insert`:
       - Validate that the buffer size is greater than or equal to the sum of the position and the length of the string.

    :param ext_call_node: The call node representing the external function call.
    :type ext_call_node: pysvf.CallICFGNode
    """
    def updateStateOnExtCall(self, extCallNode: pysvf.CallICFGNode):
        func_name = extCallNode.getCalledFunction().getName()

        # Handle external calls
        # TODO: handle external calls
        # void mem_insert(void *buffer, const void *data, size_t data_size, size_t position);
        if func_name == "mem_insert":
            # void mem_insert(void *buffer, const void *data, size_t data_size, size_t position);
            # Check sizeof(buffer) >= position + data_size
            abstract_state = self.post_abs_trace[extCallNode]
            assert isinstance(abstract_state, AbstractState)
            buffer_id = extCallNode.getArgument(0).getId()
            position_id = extCallNode.getArgument(3).getId()
            data_size_id = extCallNode.getArgument(2).getId()

            for addr in abstract_state[buffer_id].getAddrs():
                obj_id = abstract_state.getIDFromAddr(addr)
                obj_size = self.svfir.getBaseObject(obj_id).getByteSizeOfObj()
                access_offset = abstract_state[position_id].getInterval() + abstract_state[data_size_id].getInterval()

                if int(access_offset.ub()) > obj_size:
                    msg = "Buffer overflow detected. Objsize: {}, but try to access offset {}".format(obj_size, access_offset)
                    self.buf_overflow_helper.reportBufOverflow(extCallNode, msg)
                else:
                    self.buf_overflow_helper.handleMemcpy(abstract_state, extCallNode.getArgument(0), extCallNode.getArgument(1), abstract_state[data_size_id].getInterval(), abstract_state[position_id].getInterval().getIntNumeral())
        # TODO: handle external calls
        # void str_insert(void *buffer, const void *data, size_t position);
        elif func_name == "str_insert":
            # void str_insert(void *buffer, const void *data, size_t position);
            # Check sizeof(buffer) >= position + strlen(data)
            abstract_state = self.post_abs_trace[extCallNode]
            buffer_id = extCallNode.getArgument(0).getId()
            position_id = extCallNode.getArgument(2).getId()
            strlen = self.buf_overflow_helper.getStrlen(abstract_state, extCallNode.getArgument(1))

            for addr in abstract_state[buffer_id].getAddrs():
                obj_id = abstract_state.getIDFromAddr(addr)
                obj_size = self.svfir.getBaseObject(obj_id).getByteSizeOfObj()
                access_offset = abstract_state[position_id].getInterval() + strlen

                if int(access_offset.ub()) > obj_size:
                    msg = f"Buffer overflow detected. Objsize: {obj_size}, but try to access offset {access_offset}"
                    self.buf_overflow_helper.reportBufOverflow(extCallNode, msg)
                else:
                    self.buf_overflow_helper.handleMemcpy(abstract_state, extCallNode.getArgument(0), extCallNode.getArgument(1), strlen, abstract_state[position_id].getInterval().getIntNumeral())


    # string/memory external API handlers used in func_map
    def _sse_strlen(self, call_node: pysvf.CallICFGNode):
        as_ = self.post_abs_trace[call_node]
        str_val = call_node.getArgument(0)
        length_iv = self.buf_overflow_helper.getStrlen(as_, str_val)
        ret = call_node.getRetICFGNode().getActualRet()
        if ret:
            as_[ret.getId()] = AbstractValue(length_iv)

    def _handle_strcpy(self, call_node: pysvf.CallICFGNode):
        as_ = self.post_abs_trace[call_node]
        dst = call_node.getArgument(0)
        src = call_node.getArgument(1)
        strlen_src = self.buf_overflow_helper.getStrlen(as_, src)
        self._handle_memcpy(as_, dst, src, strlen_src, 0)

    def _handle_strcat(self, call_node: pysvf.CallICFGNode):
        as_ = self.post_abs_trace[call_node]
        dst = call_node.getArgument(0)
        src = call_node.getArgument(1)
        strlen_dst = self.buf_overflow_helper.getStrlen(as_, dst)
        strlen_src = self.buf_overflow_helper.getStrlen(as_, src)
        start_idx = int(strlen_dst.lb().getNumeral())
        self._handle_memcpy(as_, dst, src, strlen_src, start_idx)

    def _handle_memcpy(self, abstract_state: pysvf.AbstractState, dst: pysvf.SVFVar, src: pysvf.SVFVar, length: pysvf.IntervalValue, start_idx: int):
        self.buf_overflow_helper.handleMemcpy(abstract_state, dst, src, length, start_idx)

    def _handle_memset(self, abstract_state: pysvf.AbstractState, dst: pysvf.SVFVar, elem: pysvf.IntervalValue, length: pysvf.IntervalValue):
        dst_id = dst.getId()
        elem_size = 1
        if isinstance(dst, pysvf.ValVar):
            if dst.getType().isArrayTy():
                elem_size = dst.getType().getTypeOfElement().getByteSize()
            elif dst.getType().isPointerTy():
                et = abstract_state.getPointeeElement(dst_id)
                if et and et.isArrayTy():
                    elem_size = et.getTypeOfElement().getByteSize()
                elif et:
                    elem_size = et.getByteSize()
                else:
                    elem_size = 1
            else:
                return
        size = int(length.lb().getNumeral())
        if elem_size <= 0:
            return
        count = size // elem_size
        if abstract_state.inVarToAddrsTable(dst_id):
            for index in range(0, int(count)):
                addrs = abstract_state.getGepObjAddrs(dst_id, pysvf.IntervalValue(index))
                for addr in addrs:
                    abstract_state.store(addr, AbstractValue(elem))

    # ---- Buffer Overflow Detector (port of C++ AEDetector buf overflow parts) ----
    def detectExtAPIBufOverflow(self, call: pysvf.CallICFGNode):
        as_ = self.post_abs_trace[call]
        fun = call.getCalledFunction()
        if not fun:
            return
        name = fun.getName()
        # strcpy/strcat groups
        if name in ("strcpy", "__strcpy_chk", "stpcpy", "wcscpy", "__wcscpy_chk"):
            if not self._detect_strcpy(as_, call):
                msg = f"Buffer overflow suspected in {name}"
                self.buf_overflow_helper.reportBufOverflow(call, msg)
            return
        if name in ("__strcat_chk", "strcat", "__wcscat_chk", "wcscat", "__strncat_chk", "strncat", "__wcsncat_chk", "wcsncat"):
            if not self._detect_strcat(as_, call):
                msg = f"Buffer overflow suspected in {name}"
                self.buf_overflow_helper.reportBufOverflow(call, msg)
            return
        # memcpy/memset families via rules
        if hasattr(self, "ext_api_buf_rules") and name in self.ext_api_buf_rules:
            pairs = self.ext_api_buf_rules[name]
            for buf_idx, size_idx in pairs:
                size_iv = as_[call.getArgument(size_idx).getId()].getInterval() - IntervalValue(1, 1)
                buf_var = call.getArgument(buf_idx)
                if not self._canSafelyAccessMemory(as_, buf_var, size_iv):
                    msg = f"Buffer overflow suspected in {name} at arg{buf_idx} with size arg{size_idx}"
                    self.buf_overflow_helper.reportBufOverflow(call, msg)
            return

    def _detect_strcpy(self, abstract_state: pysvf.AbstractState, call: pysvf.CallICFGNode) -> bool:
        dst = call.getArgument(0)
        src = call.getArgument(1)
        strlen_src = self.buf_overflow_helper.getStrlen(abstract_state, src)
        return self._canSafelyAccessMemory(abstract_state, dst, strlen_src)

    def _detect_strcat(self, abstract_state: pysvf.AbstractState, call: pysvf.CallICFGNode) -> bool:
        name = call.getCalledFunction().getName()
        strcat_group = {"__strcat_chk", "strcat", "__wcscat_chk", "wcscat"}
        strncat_group = {"__strncat_chk", "strncat", "__wcsncat_chk", "wcsncat"}
        if name in strcat_group:
            dst = call.getArgument(0)
            src = call.getArgument(1)
            strlen_dst = self.buf_overflow_helper.getStrlen(abstract_state, dst)
            strlen_src = self.buf_overflow_helper.getStrlen(abstract_state, src)
            total = strlen_dst + strlen_src
            return self._canSafelyAccessMemory(abstract_state, dst, total)
        elif name in strncat_group:
            dst = call.getArgument(0)
            n_iv = abstract_state[call.getArgument(2).getId()].getInterval()
            strlen_dst = self.buf_overflow_helper.getStrlen(abstract_state, dst)
            total = strlen_dst + n_iv
            return self._canSafelyAccessMemory(abstract_state, dst, total)
        else:
            return True

    def _canSafelyAccessMemory(self, abstract_state: pysvf.AbstractState, value: pysvf.SVFVar, length_iv: pysvf.IntervalValue) -> bool:
        value_id = value.getId()
        if not abstract_state[value_id].isAddr():
            return True
        for addr in abstract_state[value_id].getAddrs():
            obj_id = abstract_state.getIDFromAddr(addr)
            base_obj = self.svfir.getBaseObject(obj_id)
            # compute size
            if base_obj.isConstantByteSize():
                size = base_obj.getByteSizeOfObj()
            else:
                icfg_node = base_obj.getICFGNode()
                size = 0
                for stmt2 in icfg_node.getSVFStmts():
                    if isinstance(stmt2, pysvf.AddrStmt):
                        size = abstract_state.getAllocaInstByteSize(stmt2)
            # compute offset
            offset = IntervalValue(0)
            gnode = self.svfir.getGNode(obj_id)
            try:
                gep_obj = gnode.asGepObjVar()
                if self.buf_overflow_helper.hasGepObjOffsetFromBase(gep_obj):
                    offset = self.buf_overflow_helper.getGepObjOffsetFromBase(gep_obj) + length_iv
                else:
                    offset = length_iv
            except Exception:
                offset = length_iv
            if int(offset.ub()) >= size:
                return False
        return True

    """
    Handle ICFG nodes in a cycle using widening and narrowing operators.
    
    This function implements abstract interpretation for cycles in the ICFG using widening and narrowing
    operators to ensure termination. It processes all ICFG nodes within a cycle and implements
    widening-narrowing iteration to reach fixed points twice: once for widening (to ensure termination)
    and once for narrowing (to improve precision).
    
    :param cycle: The WTO cycle containing ICFG nodes to be processed
    :type cycle: ICFGWTOCycle
    """
    def handleICFGCycle(self, cycle: ICFGWTOCycle, context_depth: int):
        head = cycle.head.node
        increasing = True
        iteration = 0
        widen_delay = self.widen_delay  # Use class member for widen delay

        while True:
            # Get the abstract state of the cycle head 
            # pre_iteration_as is the postAbsTrace[head] of the cycle head before the current iteration
            # cur_iteration_as is the postAbsTrace[head] of the cycle head at the current iteration
            pre_iteration_as = self.post_abs_trace[head] if head in self.post_abs_trace else None
            self.handleICFGNode(head, context_depth)  # Handle the cycle head node
            cur_iteration_as = self.post_abs_trace[head]

            if iteration >= widen_delay:
                if increasing:
                    # widening
                    self.post_abs_trace[head] = pre_iteration_as.widening(cur_iteration_as)
                    if self.post_abs_trace[head] == pre_iteration_as:
                        increasing = False
                        continue
                else:
                    # narrowing
                    self.post_abs_trace[head] = pre_iteration_as.narrowing(cur_iteration_as)
                    if self.post_abs_trace[head] == pre_iteration_as:
                        break

            # Handle the cycle components	
            for comp in cycle.components:
                if isinstance(comp, ICFGWTONode):
                    self.handleICFGNode(comp.node, context_depth)
                elif isinstance(comp, ICFGWTOCycle):
                    # Handle the sub cycle (nested cycle)
                    self.handleICFGCycle(comp, context_depth)

            iteration += 1







