/*
 * SPDX-FileType: SOURCE
 * SPDX-License-Identifier: EUPL-1.2+
 * SPDX-FileCopyrightText: 2021 Anna “CyberTailor” <cyber@sysrq.in>
 */

#include <sys/types.h>

#include <assert.h>
#include <ctype.h>
#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>

#include <mandoc/mandoc.h>
#include <mandoc/roff.h>
#include <mandoc/mandoc_parse.h>

extern char	*program_invocation_short_name;

#define		 VAR_SUB_COUNT 4
const char	*var_subsections[VAR_SUB_COUNT] = { "Required variables",
						    "Optional variables",
						    "Output variables",
						    "User variables" };

enum	mquerylevel {
	MQUERYLEVEL_OK = 0, /* succesful query */
	MQUERYLEVEL_NOTFOUND, /* failed query */
	MQUERYLEVEL_ERROR,  /* invalid input document */
	MQUERYLEVEL_UNSUPP, /* input needs unimplemented features */
	MQUERYLEVEL_BADARG, /* bad argument in invocation */
	MQUERYLEVEL_SYSERR, /* system error */
	MQUERYLEVEL_MAX
};

struct	enclosure {
	const char	*before;
	const char	*after;
};

int	global_query(struct roff_node *mdoc, char opt);
int	function_query(struct roff_node *mdoc, const char *funcname, char opt);
int	variable_query(struct roff_node *mdoc, const char *varname, char opt);

int	print_item_heads(struct roff_node *n, enum roff_tok macro, int errflag);
int	print_item_bodies(struct roff_node *n, enum roff_tok macro,
		const char prepend_text[], int errflag);

static void	pstring(const char *p, int flags);
int		deroff_print(const struct roff_node *n);

struct roff_node	*first_node_by_macro(struct roff_node *n,
				enum roff_tok macro, int errflag);
struct roff_node	*first_node_by_name(struct roff_node *n,
				const char section_name[], int errflag);

/*
 * Search for macro name recursively.
 */
struct roff_node *
first_node_by_macro(struct roff_node *n, enum roff_tok macro, int errflag)
{
	struct roff_node	*nfound;

	if (n == NULL)
		return NULL;

	for (; n != NULL; n = n->child) {
		if (n->tok == macro)
			return n;

		nfound = first_node_by_macro(n->next, macro, 0);
		if (nfound != NULL)
			return nfound;
	}

	if (!errflag)
		return NULL;
	errx((int)MQUERYLEVEL_NOTFOUND, "macro %d not found", macro);
}

/*
 * Search for header text recursively.
 */
struct roff_node *
first_node_by_name(struct roff_node *n, const char section_name[], int errflag)
{
	struct roff_node	*nfound;
	char			*head_text = NULL;

	if (n == NULL)
		return NULL;

	for (; n != NULL; n = n->child) {
		if(n->head != NULL) {
			deroff(&head_text, n->head);
			if (head_text != NULL && strcasecmp(head_text, section_name) == 0)
				return n;
		}

		nfound = first_node_by_name(n->next, section_name, 0);
		if (nfound != NULL)
			return nfound;
	}

	if (!errflag)
		return NULL;
	errx((int)MQUERYLEVEL_NOTFOUND, "section not found: %s", section_name);
}

/*
 * Strip the escapes out of a string, emitting the results.
 */
static void
pstring(const char *p, int flags)
{
	char		last_ch = '\0';
	enum mandoc_esc	esc;

	/* strip spaces at the beginning of line */
	while (' ' == *p) {
		if ((flags & NODE_NOFILL) != 0)
			putchar((unsigned char )*p);
		p++;
	}

	while ('\0' != *p)
		if ('\\' == *p) {
			p++;
			esc = mandoc_escape(&p, NULL, NULL);
			if (ESCAPE_ERROR == esc)
				break;
		} else {
			/* strip last space at the end of line */
			if ('\0' == *(p+1) && ' ' == *p)
				break;
			/* strip consecutive spaces */
			if (' ' == last_ch && ' ' == *p)
				if ((flags & NODE_NOFILL) != 0) {
					p++;
					continue;
				}
			last_ch = *p;
			putchar((unsigned char )*p++);
		}
}

/*
 * Lame and buggy as hell reimplementation of deroff().
 */
int
deroff_print(const struct roff_node *n)
{
	enum roff_type		ntype;
	struct enclosure	enc_text = { "", "" },
				enc_macro = { " ", " " };

	assert(n);
	assert(n->parent);

	if ((n->flags & NODE_NOPRT) != 0)
		return (int)MQUERYLEVEL_OK;

	switch (n->tok) {
		/* handle '.An -split' */
		case MDOC_An:
			enc_macro.before = "";
			if (n->child == NULL) {
				enc_macro.after = "";
			}
			break;
		/* print each author on a separate line */
		case MDOC_Aq:
			enc_macro.before = "<";
			enc_macro.after = ">\n";
			break;
		/* two newlines and @CODE before display blocks */
		case MDOC_Bd:
			enc_macro.before = "\n\n@CODE\n";
			enc_macro.after = "@CODE\n";
			break;
		/* replace .Pp with two newlines */
		case MDOC_Pp:
			enc_macro.before = "\n";
			enc_macro.after = "\n";
			break;
		case MDOC_Pq:
			enc_macro.before = " (";
			enc_macro.after = ") ";
			break;
		/* keep spacing for inlined macros */
		case MDOC_Nm:
		case MDOC_Pa:
			break;
		default:
			if ((n->flags & NODE_LINE) != 0 || n->parent->tok == MDOC_It)
				enc_macro.before = "";
			break;
	}

	switch (n->parent->tok) {
		case MDOC_Aq:
			enc_macro.before = "";
			enc_macro.after = "";
			break;
		default:
			break;
	}

	ntype = n->type;
	if (ntype != ROFFT_TEXT) {
		if (ntype == ROFFT_BLOCK || ntype == ROFFT_ELEM)
			fputs(enc_macro.before, stdout);

		for (n = n->child; n != NULL; n = n->next)
			deroff_print(n);

		if (ntype == ROFFT_BLOCK || ntype == ROFFT_ELEM)
			fputs(enc_macro.after, stdout);

		return (int)MQUERYLEVEL_OK;
	}

	/* do not print trailing space before newline */
	if (n->next == NULL && n->parent->next != NULL)
		if (n->parent->next->tok == MDOC_Pp)
			enc_text.after = "";
	/* print link's description in parentheses */
	if (n->parent->tok == MDOC_Lk && n->prev != NULL) {
		enc_text.before = " (";
		enc_text.after = ")";
	}
	/* handle display blocks */
	if (n->flags & NODE_NOFILL)
		enc_text.after = "\n";

	fputs(enc_text.before, stdout);
	pstring(n->string, n->flags);
	fputs(enc_text.after, stdout);

	return (int)MQUERYLEVEL_OK;
}

/*
 * Used to print lists of functions and variables.
 * Expects '.Bl' list's body and name of the macro following '.It'.
 * This function is not recursive.
 */
int
print_item_heads(struct roff_node *n, enum roff_tok macro, int errflag)
{
	const struct roff_node *element;
	int			found = 0;

	assert(n);
	for (n = n->child; n != NULL; n = n->next) {
		if (n->tok != MDOC_It)
			continue; /* mandoc -Tlint will give a warning */

		element = n->head->child;
		if (element == NULL) {
			warnx("%d:%d: empty item header", n->line, n->pos);
			continue;
		}

		if (element->tok != macro)
			continue;

		found = 1;
		deroff_print(element);
		puts("");
	}

	if (!found && errflag)
		errx((int)MQUERYLEVEL_NOTFOUND, "no matching items found");
	return (int)MQUERYLEVEL_OK;
}

/*
 * Used to print links from the "See also" section.
 * Expects '.Bl' list's body and name of the macro following '.It'.
 * This function is not recursive.
 */
int
print_item_bodies(struct roff_node *n, enum roff_tok macro,
		const char prepend_text[], int errflag)
{
	const struct roff_node *element;
	int			found = 0;

	assert(n);
	for (n = n->child; n != NULL; n = n->next) {
		if (n->tok != MDOC_It)
			continue; /* mandoc -Tlint will give a warning */

		element = n->body->child;
		if (element == NULL) {
			warnx("%d:%d: empty item body", n->line, n->pos);
			continue;
		}

		if (element->tok != macro)
			continue;

		/*
		 * special case for links - skip links without text
		 */
		if (element->tok == MDOC_Lk && element->child->next == NULL)
			continue;

		if (!found) {
			printf("%s", prepend_text);
			found = 1;
		}

		deroff_print(element);
		puts("");
	}

	if (!found && errflag)
		errx((int)MQUERYLEVEL_NOTFOUND, "no matching items found");
	return (int)MQUERYLEVEL_OK;
}

int
global_query(struct roff_node *mdoc, char opt)
{
	struct roff_node	*nfound, *nvars;

	switch (opt) {
	/* blurb */
	case 'B':
		nfound = first_node_by_name(mdoc, "NAME", 1);
		nfound = first_node_by_macro(nfound->body, MDOC_Nd, 1);
		return deroff_print(nfound);
	/* description */
	case 'D':
		nfound = first_node_by_name(mdoc, "DESCRIPTION", 1);
		deroff_print(nfound->body);

		nfound = first_node_by_name(mdoc, "SEE ALSO", 0);
		if (nfound != NULL) {
			nfound = first_node_by_macro(nfound->body, MDOC_Bl, 1);
			return print_item_bodies(nfound->body, MDOC_Lk,
						 "\n\nReferences:\n", 0);
		}
		return (int)MQUERYLEVEL_OK;
	/* function list */
	case 'F':
		nfound = first_node_by_name(mdoc, "FUNCTIONS", 1);
		nfound = first_node_by_macro(nfound->body, MDOC_Bl, 1);
		return print_item_heads(nfound->body, MDOC_Ic, 1);
	/* eclass variable list */
	case 'V':
		nvars = first_node_by_name(mdoc, "ECLASS VARIABLES", 1);
		for (int i = 0; i < VAR_SUB_COUNT; ++i) {
			nfound = first_node_by_name(mdoc, var_subsections[i], 0);
			if (nfound == NULL)
				continue;

			nfound = first_node_by_macro(nfound->body, MDOC_Bl, 1);
			print_item_heads(nfound->body, MDOC_Dv, 0);
			print_item_heads(nfound->body, MDOC_Ev, 0);
			print_item_heads(nfound->body, MDOC_Va, 0);
		}
		return (int)MQUERYLEVEL_OK;
	/* authors */
	case 'a':
		nfound = first_node_by_name(mdoc, "AUTHORS", 1);
		return deroff_print(nfound->body);
	/* reporting bugs */
	case 'b':
		nfound = first_node_by_name(mdoc, "REPORTING BUGS", 1);
		nfound = first_node_by_macro(nfound->body, MDOC_Lk, 1);
		return deroff_print(nfound->child);
	/* deprecation check */
	case 'd':
		nfound = first_node_by_name(mdoc, "DEPRECATED", 1);
		return deroff_print(nfound->body);
	/* examples */
	case 'e':
		nfound = first_node_by_name(mdoc, "EXAMPLES", 1);
		return deroff_print(nfound->body);
	/* maintainers */
	case 'm':
		nfound = first_node_by_name(mdoc, "MAINTAINERS", 1);
		return deroff_print(nfound->body);
	default:
		errx((int)MQUERYLEVEL_UNSUPP, "option is not implemented");
	}
}

int
function_query(struct roff_node *mdoc, const char *funcname, char opt)
{
	switch (opt) {
	default:
		errx((int)MQUERYLEVEL_UNSUPP, "option is not implemented");
	}
}

int
variable_query(struct roff_node *mdoc, const char *varname, char opt)
{
	switch (opt) {
	default:
		errx((int)MQUERYLEVEL_UNSUPP, "option is not implemented");
	}
}

int
main(int argc, char *argv[])
{
	struct roff_meta       *meta;
	struct mparse	       *mp;
	const char	       *fnin = NULL, *itemname = NULL, *optstring;
	int			functionq, variableq, flagc, fd, exit_status;
	char			ch, flag = '\0';

	functionq = 0;
	variableq = 0;
	optstring = "BDFVabdem";
	if (strcasecmp(program_invocation_short_name, "mquery-function") == 0) {
		functionq = 1;
		optstring = "DdiruF:";
	}
	if (strcasecmp(program_invocation_short_name, "mquery-variable") == 0) {
		variableq = 1;
		optstring = "DdiopruV:";
	}

	flagc = 0;
	while ((ch = getopt(argc, argv, optstring)) != -1) {
		switch (ch) {
		case 'B':
		case 'D':
		case 'a':
		case 'b':
		case 'd':
		case 'i':
		case 'e':
		case 'm':
		case 'o':
		case 'p':
		case 'r':
		case 'u':
			flag = ch;
			++flagc;
			break;
		case 'F':
		case 'V':
			if (functionq || variableq)
				itemname = optarg;
			else {
				flag = ch;
				++flagc;
			}
			break;
		default:
			goto usage;
		}
	}

	argc -= optind;
	argv += optind;

	if (argc != 1 || flagc != 1)
		goto usage;
	if (itemname == NULL && (functionq || variableq))
		goto usage;

	mchars_alloc();
	mp = mparse_alloc(MPARSE_MDOC | MPARSE_VALIDATE | MPARSE_UTF8,
			  MANDOC_OS_OTHER, NULL);
	assert(mp);

	fnin = argv[0];
	if ((fd = mparse_open(mp, fnin)) == -1)
		err((int)MQUERYLEVEL_BADARG, "%s", fnin);
	mparse_readfd(mp, fd, fnin);
	close(fd);
	meta = mparse_result(mp);

	if (meta == NULL)
		errx((int)MQUERYLEVEL_ERROR, "could not parse %s", fnin);
	if (meta->macroset != MACROSET_MDOC)
		errx((int)MQUERYLEVEL_ERROR, "not an mdoc document: %s", fnin);

	if (functionq)
		exit_status = function_query(meta->first->child, itemname, flag);
	if (variableq)
		exit_status = variable_query(meta->first->child, itemname, flag);
	exit_status = global_query(meta->first->child, flag);

	mparse_free(mp);
	mchars_free();
	return exit_status;

usage:
	if (functionq)
		fprintf(stderr,
			"usage: mquery-function -D|d|i|r|u\n"
			"                       -F function file\n");
	else if (variableq)
		fprintf(stderr,
			"usage: mquery-variable -D|d|i|o|p|r|u\n"
			"                       -V variable file\n");
	else
		fprintf(stderr,
			"usage: mquery -B|D|F|V|a|b|d|e|m file\n");
	return (int)MQUERYLEVEL_BADARG;
}
