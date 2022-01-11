<!-- .slide: data-state="cover-alternate" id="cover-page-alternate" data-timing="20" data-menu-title="Cover slide (alternate)" -->
<div class="title">
    <h1>Automating Code Review with Sparse</h1>
	<h2>Project specific static analysis of a large C codebase</h2>
</div>

<div class="date-location">FOSDEM 2022</div>


<!-- .slide: data-state="normal toc" id="contact" data-timing="20s" data-menu-title="Contact" -->
#  Contact

1. Richard Palethorpe
> [richiejp.com](https://richiejp.com) / rpalethorpe@suse.com

2. Linux Test Project
> [github.com/linux-test-project](https://github.com/linux-test-project)

3. Sparse Project
> linux-sparse@vger.kernel.org

4. SUSE Linux
> [suse.com](https://www.suse.com/)


<!-- .slide: data-state="normal" id="what-is-race" data-timing="20s" data-menu-title="What is a data race?" -->
# What is Sparse

- A C static analysis library
- A Linux kernel static analysis tool
- A "simple" C compiler written in C
- Yet another Linus Torvalds project
- Possibly other stuff Richard doesn't know about


<!-- .slide: data-state="normal" id="what-is-kernel-race" data-timing="20s" data-menu-title="What else is Sparse used for" -->
# What is Sparse used for?

Other than what I am talking about today...

- Implementing C attributes useful for the kernel, e.g.
  + Pointer namespaces: `__attribute__((address_space(name)))`
  + Matching entry and exit contexts (usually whether locks are held/released)
	`__attribute__((context(name, entry, exit)))`
- Implementing checks useful for the kernel
- Implementing general checks quickly
- As a research compiler?


<!-- .slide: data-state="normal" id="what-is-reproducer" data-timing="20s" data-menu-title="What is the LTP?" -->
# What is the LTP?

The Linux Test Project is...

- A collection of kernel feature tests
- A collection of kernel bug reproducers
- A framework for writing tests in C and Shell
- A home for orphaned projects such as the Open POSIX compliance tests

*SUSE is the top contributor in recent years and uses it to detect issues early.*


<!-- .slide: data-state="normal" id="simple-race-1" data-timing="20s" data-menu-title="A simple race" -->
# What does LTP currently use it for?

- Checking `TST_RET` and `TST_ERR` variables are not overwritten by
  the test library
- Checking `tst_` is prefixed to public test library functions
- Checking the static keyword is used
- Checking `tst_tag` arrays are statically initialized with the sentinel value `{ }`


<!-- .slide: data-state="normal" id="simple-race-1" data-timing="20s" data-menu-title="A simple race" -->
# Why does LTP use it

- We can only rely on contributors having (an old version of) GCC
- We are *very* motivated to reduce our review workload
- Sparse is easy to vendor in to LTP and ~force~ encourage contributors to use it
  + Written in C with only GCC and stdlib as dependencies
  + Compiles and runs wherever Linux does
  + Used by Linux itself
- Powerful enough to solve any issue we have tried

For more see: https://richiejp.com/custom-c-static-analysis-tools


<!-- .slide: data-state="normal" id="simple-race-2" data-timing="20s" data-menu-title="A simple diagram" -->
# How does Sparse work?

- Hand written lexer creates a token list
- Tokens are parsed into "symbols"
  + These initially resemble an AST (abstract syntax tree) or DAG
    (directed acyclic graph).
- Preprocessing is done and macro symbols are expanded
- Some symbols are expanded or reduced (e.g static algebraic
  expressions are simplified)
- The symbols are "linearized" into "basicblocks" IR:
  + basicblocks are *linear* sequences of instructions;
	Like simplified assembly with no jumps or loops
  + basicblocks are chained together into a graph (by jumps)
- The basicblocks are converted into SSA (single static assigment) form

It continues...


<!-- .slide: data-state="normal" id="simple-race-3" data-timing="20s" data-menu-title="Simple plots" -->
# How does Sparse work? cont.

- Something involving a dominance tree to help analyze control flow
- Magic?

Eventually we get a simplified graph of basicblocks! Similar to LLVM
IR (intermediate representation).


<!-- .slide: data-state="normal" id="sendmsg03-1" data-timing="20s" data-menu-title="sendmsg03 1" -->
# How do we use this to perform the LTP checks?

- We operate on two levels
  + The AST/DAG (symbols)
  + The linearized IR (basicblocks and instructions)
- We use the linearized form to find store instructions with `TST_RET`
  or `TST_ERR` as the destination
- We inspect the symbols representing function and variable
  defintions to see if they should be static or have the `tst_`
  prefix
- We use the symbols to check the `tst_tag` array is terminated with `{ }`


<!-- .slide: data-state="normal" id="sendmsg03-2" data-timing="20s" data-menu-title="sendmsg03 2" -->
# The `TST_RET` and `TST_ERR` check

- Helper macros like `TEST` and the `TST_EXP_*` write to these globals
- Only test code should write to these to avoid silently overwriting
  an error value
- Various library functions were using the `TEST` macro or modifying
  the vars directly

E.g.

```c
int tst_alg_create(void)
{
	TEST(socket(AF_ALG, SOCK_SEQPACKET, 0));
	if (TST_RET >= 0)
		return TST_RET;
	if (TST_ERR == EAFNOSUPPORT)
		tst_brk(TCONF, "kernel doesn't support AF_ALG");
	tst_brk(TBROK | TTERRNO, "unexpected error creating AF_ALG socket");
	return -1;
}
```


<!-- .slide: data-state="normal" id="sendmsg03-2" data-timing="20s" data-menu-title="sendmsg03 2" -->
The `TST_RET` and `TST_ERR` implementation. Short and "simple"

```c
static void check_lib_sets_TEST_vars(const struct instruction *insn)
{
	static struct ident *TST_RES_id, *TST_ERR_id;

	if (!TST_RES_id) {
		TST_RES_id = built_in_ident("TST_RET");
		TST_ERR_id = built_in_ident("TST_ERR");
	}

	if (insn->opcode != OP_STORE)
		return;
	if (insn->src->ident != TST_RES_id &&
	    insn->src->ident != TST_ERR_id)
		return;

	warning(insn->pos,
		"LTP-002: Library should not write to TST_RET or TST_ERR");
}
```

Note that we check every instruction in library objects


<!-- .slide: data-state="normal" id="sendmsg03-3" data-timing="20s" data-menu-title="sendmsg03 3" -->
# The symbol visibility check

* Make sure symbols that can be static are static
* Make sure LTP API symbols start with `tst_` or similar
* Standard practice in C to avoid link time issues, but easy to forget
* Allows exotic compilation: linking multiple tests into a single object

e.g. Test author forgot to make some test callbacks static

```c
static void run(void) { ... } /* correct */
void setup(void) { ... } /* wrong */

static struct tst_test test = {
	.test_all = run,
	.setup = setup,
	...
}
```


<!-- .slide: data-state="normal" id="sendmsg03-3" data-timing="20s" data-menu-title="sendmsg03 3" -->
The symbol visibility (static) check. Too long to fit on a slide, but...

```c
static void check_symbol_visibility(const struct symbol *const sym)
{
	const unsigned long mod = sym->ctype.modifiers;
	const char *const name = show_ident(sym->ident);
	const int has_lib_prefix = !strncmp("tst_", name, 4) ||
		!strncmp("TST_", name, 4) ||
		!strncmp("ltp_", name, 4) ||
		!strncmp("safe_", name, 5);

	if (!(mod & MOD_TOPLEVEL))
		return;

	if (has_lib_prefix && (mod & MOD_STATIC) && !(mod & MOD_INLINE)) {
		warning(sym->pos,
			"LTP-003: Symbol '%s' has the LTP public library prefix, but is static (private).",
			name);
		return;
	}

	if ((mod & MOD_STATIC))
		return;

	if (tu_kind == LTP_LIB && !has_lib_prefix) {
		warning(sym->pos,
			"LTP-003: Symbol '%s' is a public library function, but is missing the 'tst_' prefix",
			name);
		return;
	}

	if (sym->same_symbol)
		return;

	if (sym->ident == &main_ident)
		return;

	warning(sym->pos,
		"Symbol '%s' has no prototype or library ('tst_') prefix. Should it be static?",
		name);
}
```


<!-- .slide: data-state="normal" id="sendmsg03-3" data-timing="20s" data-menu-title="sendmsg03 3" -->
# The `tst_tag` null terminator check

* Tests can be tagged with info such as kernel Git commit and CVE number
* These are stored in the `test.tags` array which is *only* accessed
  when the test *fails*
* It is an `{}` (empty struct) terminated array. The library segfaults without it
* Tags are often appended to tests after the initial commit and not
  tested on a buggy kernel

e.g. Test author forgot to add `{}` at the end

```c
static struct tst_test test = {
	...
	.tags = (const struct tst_tag[]){
		{"linux-git", "ce683e5f9d04"},
		{"CVE", "CVE-2016-4997"},
		/* Should be {} here */
	}
};
```


<!-- .slide: data-state="normal" id="sendmsg03-4" data-timing="20s" data-menu-title="sendmsg03 4" -->
The `tst_tag` null terminator implementation. Not a huge amount of code, but...

```c
static bool is_terminated_with_null_struct(const struct symbol *const sym)
{
	const struct expression *const arr_init = sym->initializer;
	const struct expression *item_init =
		last_ptr_list((struct ptr_list *)arr_init->expr_list);

	if (item_init->type == EXPR_POS)
		item_init = item_init->init_expr;

	return ptr_list_empty((struct ptr_list *)item_init->expr_list);
}

static void check_tag_initializer(const struct symbol *const sym)
{
	if (is_terminated_with_null_struct(sym))
		return;

	warning(sym->pos,
		"LTP-005: test.tags array doesn't appear to be null-terminated; did you forget to add '{}' as the final entry?");
}

static void check_test_struct(const struct symbol *const sym)
{
	static struct ident *tst_test, *tst_test_test, *tst_tag;
	struct ident *ctype_name = NULL;
	struct expression *init = sym->initializer;
	struct expression *entry;

	if (!sym->ctype.base_type)
		return;

	ctype_name = sym->ctype.base_type->ident;

	if (!init)
		return;

	if (!tst_test_test) {
		tst_test = built_in_ident("tst_test");
		tst_test_test = built_in_ident("test");
		tst_tag = built_in_ident("tst_tag");
	}

	if (sym->ident != tst_test_test)
		return;

	if (ctype_name != tst_test)
		return;

	FOR_EACH_PTR(init->expr_list, entry) {
		if (entry->init_expr->type != EXPR_SYMBOL)
			continue;

		const struct symbol *entry_init = entry->init_expr->symbol;
		const struct symbol *entry_ctype = unwrap_base_type(entry_init);

		if (entry_ctype->ident == tst_tag)
			check_tag_initializer(entry_init);
	} END_FOR_EACH_PTR(entry);

}
```


<!-- .slide: data-state="normal" id="sendmsg03-4" data-timing="20s" data-menu-title="sendmsg03 4" -->
# Final thoughts & Questions

* Writing checks against the basicblocks IR is wonderful
* Writing checks against the AST/DAG/symbols is not so much
* Is the barrier to entry too high?
* What if compilers output a simplified AST/DAG/IR in for e.g. JSON?
* Should there be an attribute for marking arrays as null terminated?

