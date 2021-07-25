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

enum	mquerylevel {
	MQUERYLEVEL_OK = 0, /* succesful query */
	MQUERYLEVEL_NOTFOUND, /* unsuccessful query */
	MQUERYLEVEL_ERROR, /* invalid document */
	MQUERYLEVEL_UNSUPP, /* input needs unimplemented features */
	MQUERYLEVEL_BADARG, /* bad argument in invocation */
	MQUERYLEVEL_SYSERR, /* system error */
	MQUERYLEVEL_MAX
};

int	global_query(struct roff_node *mdoc, int q_blurb, int q_description,
			int q_funcs, int q_vars, int q_authors, int q_bugs,
			int q_deprecated, int q_examples, int q_maintainers);
int	function_query(struct roff_node *mdoc, const char *funcname,
			int q_description, int q_deprecated, int q_eprefix,
			int q_return, int q_usage);
int	variable_query(struct roff_node *mdoc, const char *varname,
			int q_description, int q_deprecated, int q_eprefix,
			int q_output, int q_preinherit, int q_required, int q_user);

int
global_query(struct roff_node *mdoc, int q_blurb, int q_description,
		int q_funcs, int q_vars, int q_authors, int q_bugs,
		int q_deprecated, int q_examples, int q_maintainers)
{
	errx((int)MQUERYLEVEL_UNSUPP, "option is not implemented");
}

int
function_query(struct roff_node *mdoc, const char *funcname, int q_description,
		int q_deprecated, int q_eprefix, int q_return, int q_usage)
{
	errx((int)MQUERYLEVEL_UNSUPP, "option is not implemented");
}

int
variable_query(struct roff_node *mdoc, const char *varname, int q_description,
		int q_deprecated, int q_eprefix, int q_output,
		int q_preinherit, int q_required, int q_user)
{
	errx((int)MQUERYLEVEL_UNSUPP, "option is not implemented");
}

int
main(int argc, char *argv[])
{
	struct roff_meta       *meta;
	struct mparse	       *mp;
	const char	       *fnin = NULL, *funcname = NULL, *varname = NULL,
			       *optstring = "BDFVabdem";
	int			Bflag = 0, Dflag = 0, Fflag = 0, Vflag = 0,
				aflag = 0, bflag = 0, dflag = 0, eflag = 0,
				iflag = 0, mflag = 0, oflag = 0, pflag = 0,
				rflag = 0, uflag = 0, flagc = 0, ch, fd,
				functionq = 0, variableq = 0,
				exit_status = (int)MQUERYLEVEL_ERROR;

	if (strcasecmp(program_invocation_short_name, "mquery-function") == 0) {
		functionq = 1;
		optstring = "DdiruF:";
	}
	if (strcasecmp(program_invocation_short_name, "mquery-variable") == 0) {
		variableq = 1;
		optstring = "DdiopruV:";
	}

	while ((ch = getopt(argc, argv, optstring)) != -1) {
		switch (ch) {
			break; case 'F':
				if (functionq)
					funcname = optarg;
				else {
					Fflag = 1;
					++flagc;
				}
			break; case 'V':
				if (variableq)
					varname = optarg;
				else {
					Vflag = 1;
					++flagc;
				}
			break; case 'B': Bflag = 1; ++flagc;
			break; case 'D': Dflag = 1; ++flagc;
			break; case 'a': aflag = 1; ++flagc;
			break; case 'b': bflag = 1; ++flagc;
			break; case 'd': dflag = 1; ++flagc;
			break; case 'i': iflag = 1; ++flagc;
			break; case 'e': eflag = 1; ++flagc;
			break; case 'm': mflag = 1; ++flagc;
			break; case 'o': oflag = 1; ++flagc;
			break; case 'p': pflag = 1; ++flagc;
			break; case 'r': rflag = 1; ++flagc;
			break; case 'u': uflag = 1; ++flagc;
			break; default: goto usage;
		}
	}

	argc -= optind;
	argv += optind;

	if (argc != 1 || flagc != 1)
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
		exit_status = function_query(meta->first, funcname, Dflag,
					     dflag, iflag, rflag, uflag);
	if (variableq)
		exit_status = variable_query(meta->first, varname, Dflag, dflag,
				             iflag, oflag, pflag, rflag, uflag);
	exit_status = global_query(meta->first, Bflag, Dflag, Fflag, Vflag,
				   aflag, bflag, dflag, eflag, mflag);

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
