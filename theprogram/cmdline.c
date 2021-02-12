/*
  File autogenerated by gengetopt version 2.23
  generated with the following command:
  gengetopt --input=cmdline.ggo 

  The developers of gengetopt consider the fixed text that goes in all
  gengetopt output files to be in the public domain:
  we make no copyright claims on it.
*/

/* If we use autoconf.  */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef FIX_UNUSED
#define FIX_UNUSED(X) (void) (X) /* avoid warnings for unused params */
#endif

#include <getopt.h>

#include "cmdline.h"

const char *gengetopt_args_info_purpose = "Encryption of files by the symmetric\nalgorithm AES, by the public key algorithm RSA\nand the generation of RSA keys\n\nBy Rafel Amer <rafel.amer@upc.edu>";

const char *gengetopt_args_info_usage = "Usage: mcersa [OPTION]...";

const char *gengetopt_args_info_versiontext = "";

const char *gengetopt_args_info_description = "";

const char *gengetopt_args_info_help[] = {
  "  -h, --help            Print help and exit",
  "  -V, --version         Print version and exit",
  "  -i, --infile=STRING   File to encrypt or sign",
  "  -o, --outfile=STRING  Name of the encrypted or the signed file",
  "  -e, --encrypt         Encrypts a file  (default=off)",
  "  -d, --decrypt         Decrypts a file  (default=off)",
  "  -g, --genkey          Generates a pair of RSA keys  (default=off)",
  "  -b, --bits=INT        Bits of the generated RSA key  (default=`2048')",
  "  -a, --ascii           Writes the output file in ASCII format  (default=off)",
  "  -k, --keyfile=STRING  File of the public or private RSA key",
  "  -w, --show            Shows a public or private RSA key  (default=off)",
  "  -n, --noaes           Saves the RSA private key unencrypted  (default=off)",
  "  -c, --encryptkey      Encrypts an RSA private key  (default=off)",
  "  -r, --decryptkey      Decrypts an RSA private key  (default=off)",
  "  -s, --sign            Signs a file  (default=off)",
  "  -v, --verify          Verify and extract a signed file  (default=off)",
    0
};

typedef enum {ARG_NO
  , ARG_FLAG
  , ARG_STRING
  , ARG_INT
} cmdline_parser_arg_type;

static
void clear_given (struct gengetopt_args_info *args_info);
static
void clear_args (struct gengetopt_args_info *args_info);

static int
cmdline_parser_internal (int argc, char **argv, struct gengetopt_args_info *args_info,
                        struct cmdline_parser_params *params, const char *additional_error);

static int
cmdline_parser_required2 (struct gengetopt_args_info *args_info, const char *prog_name, const char *additional_error);

static char *
gengetopt_strdup (const char *s);

static
void clear_given (struct gengetopt_args_info *args_info)
{
  args_info->help_given = 0 ;
  args_info->version_given = 0 ;
  args_info->infile_given = 0 ;
  args_info->outfile_given = 0 ;
  args_info->encrypt_given = 0 ;
  args_info->decrypt_given = 0 ;
  args_info->genkey_given = 0 ;
  args_info->bits_given = 0 ;
  args_info->ascii_given = 0 ;
  args_info->keyfile_given = 0 ;
  args_info->show_given = 0 ;
  args_info->noaes_given = 0 ;
  args_info->encryptkey_given = 0 ;
  args_info->decryptkey_given = 0 ;
  args_info->sign_given = 0 ;
  args_info->verify_given = 0 ;
}

static
void clear_args (struct gengetopt_args_info *args_info)
{
  FIX_UNUSED (args_info);
  args_info->infile_arg = NULL;
  args_info->infile_orig = NULL;
  args_info->outfile_arg = NULL;
  args_info->outfile_orig = NULL;
  args_info->encrypt_flag = 0;
  args_info->decrypt_flag = 0;
  args_info->genkey_flag = 0;
  args_info->bits_arg = 2048;
  args_info->bits_orig = NULL;
  args_info->ascii_flag = 0;
  args_info->keyfile_arg = NULL;
  args_info->keyfile_orig = NULL;
  args_info->show_flag = 0;
  args_info->noaes_flag = 0;
  args_info->encryptkey_flag = 0;
  args_info->decryptkey_flag = 0;
  args_info->sign_flag = 0;
  args_info->verify_flag = 0;
  
}

static
void init_args_info(struct gengetopt_args_info *args_info)
{


  args_info->help_help = gengetopt_args_info_help[0] ;
  args_info->version_help = gengetopt_args_info_help[1] ;
  args_info->infile_help = gengetopt_args_info_help[2] ;
  args_info->outfile_help = gengetopt_args_info_help[3] ;
  args_info->encrypt_help = gengetopt_args_info_help[4] ;
  args_info->decrypt_help = gengetopt_args_info_help[5] ;
  args_info->genkey_help = gengetopt_args_info_help[6] ;
  args_info->bits_help = gengetopt_args_info_help[7] ;
  args_info->ascii_help = gengetopt_args_info_help[8] ;
  args_info->keyfile_help = gengetopt_args_info_help[9] ;
  args_info->show_help = gengetopt_args_info_help[10] ;
  args_info->noaes_help = gengetopt_args_info_help[11] ;
  args_info->encryptkey_help = gengetopt_args_info_help[12] ;
  args_info->decryptkey_help = gengetopt_args_info_help[13] ;
  args_info->sign_help = gengetopt_args_info_help[14] ;
  args_info->verify_help = gengetopt_args_info_help[15] ;
  
}

void
cmdline_parser_print_version (void)
{
  printf ("%s %s\n",
     (strlen(CMDLINE_PARSER_PACKAGE_NAME) ? CMDLINE_PARSER_PACKAGE_NAME : CMDLINE_PARSER_PACKAGE),
     CMDLINE_PARSER_VERSION);

  if (strlen(gengetopt_args_info_versiontext) > 0)
    printf("\n%s\n", gengetopt_args_info_versiontext);
}

static void print_help_common(void)
{
	size_t len_purpose = strlen(gengetopt_args_info_purpose);
	size_t len_usage = strlen(gengetopt_args_info_usage);

	if (len_usage > 0) {
		printf("%s\n", gengetopt_args_info_usage);
	}
	if (len_purpose > 0) {
		printf("%s\n", gengetopt_args_info_purpose);
	}

	if (len_usage || len_purpose) {
		printf("\n");
	}

	if (strlen(gengetopt_args_info_description) > 0) {
		printf("%s\n\n", gengetopt_args_info_description);
	}
}

void
cmdline_parser_print_help (void)
{
  int i = 0;
  print_help_common();
  while (gengetopt_args_info_help[i])
    printf("%s\n", gengetopt_args_info_help[i++]);
}

void
cmdline_parser_init (struct gengetopt_args_info *args_info)
{
  clear_given (args_info);
  clear_args (args_info);
  init_args_info (args_info);
}

void
cmdline_parser_params_init(struct cmdline_parser_params *params)
{
  if (params)
    { 
      params->override = 0;
      params->initialize = 1;
      params->check_required = 1;
      params->check_ambiguity = 0;
      params->print_errors = 1;
    }
}

struct cmdline_parser_params *
cmdline_parser_params_create(void)
{
  struct cmdline_parser_params *params = 
    (struct cmdline_parser_params *)malloc(sizeof(struct cmdline_parser_params));
  cmdline_parser_params_init(params);  
  return params;
}

static void
free_string_field (char **s)
{
  if (*s)
    {
      free (*s);
      *s = 0;
    }
}


static void
cmdline_parser_release (struct gengetopt_args_info *args_info)
{

  free_string_field (&(args_info->infile_arg));
  free_string_field (&(args_info->infile_orig));
  free_string_field (&(args_info->outfile_arg));
  free_string_field (&(args_info->outfile_orig));
  free_string_field (&(args_info->bits_orig));
  free_string_field (&(args_info->keyfile_arg));
  free_string_field (&(args_info->keyfile_orig));
  
  

  clear_given (args_info);
}


static void
write_into_file(FILE *outfile, const char *opt, const char *arg, const char *values[])
{
  FIX_UNUSED (values);
  if (arg) {
    fprintf(outfile, "%s=\"%s\"\n", opt, arg);
  } else {
    fprintf(outfile, "%s\n", opt);
  }
}


int
cmdline_parser_dump(FILE *outfile, struct gengetopt_args_info *args_info)
{
  int i = 0;

  if (!outfile)
    {
      fprintf (stderr, "%s: cannot dump options to stream\n", CMDLINE_PARSER_PACKAGE);
      return EXIT_FAILURE;
    }

  if (args_info->help_given)
    write_into_file(outfile, "help", 0, 0 );
  if (args_info->version_given)
    write_into_file(outfile, "version", 0, 0 );
  if (args_info->infile_given)
    write_into_file(outfile, "infile", args_info->infile_orig, 0);
  if (args_info->outfile_given)
    write_into_file(outfile, "outfile", args_info->outfile_orig, 0);
  if (args_info->encrypt_given)
    write_into_file(outfile, "encrypt", 0, 0 );
  if (args_info->decrypt_given)
    write_into_file(outfile, "decrypt", 0, 0 );
  if (args_info->genkey_given)
    write_into_file(outfile, "genkey", 0, 0 );
  if (args_info->bits_given)
    write_into_file(outfile, "bits", args_info->bits_orig, 0);
  if (args_info->ascii_given)
    write_into_file(outfile, "ascii", 0, 0 );
  if (args_info->keyfile_given)
    write_into_file(outfile, "keyfile", args_info->keyfile_orig, 0);
  if (args_info->show_given)
    write_into_file(outfile, "show", 0, 0 );
  if (args_info->noaes_given)
    write_into_file(outfile, "noaes", 0, 0 );
  if (args_info->encryptkey_given)
    write_into_file(outfile, "encryptkey", 0, 0 );
  if (args_info->decryptkey_given)
    write_into_file(outfile, "decryptkey", 0, 0 );
  if (args_info->sign_given)
    write_into_file(outfile, "sign", 0, 0 );
  if (args_info->verify_given)
    write_into_file(outfile, "verify", 0, 0 );
  

  i = EXIT_SUCCESS;
  return i;
}

int
cmdline_parser_file_save(const char *filename, struct gengetopt_args_info *args_info)
{
  FILE *outfile;
  int i = 0;

  outfile = fopen(filename, "w");

  if (!outfile)
    {
      fprintf (stderr, "%s: cannot open file for writing: %s\n", CMDLINE_PARSER_PACKAGE, filename);
      return EXIT_FAILURE;
    }

  i = cmdline_parser_dump(outfile, args_info);
  fclose (outfile);

  return i;
}

void
cmdline_parser_free (struct gengetopt_args_info *args_info)
{
  cmdline_parser_release (args_info);
}

/** @brief replacement of strdup, which is not standard */
char *
gengetopt_strdup (const char *s)
{
  char *result = 0;
  if (!s)
    return result;

  result = (char*)malloc(strlen(s) + 1);
  if (result == (char*)0)
    return (char*)0;
  strcpy(result, s);
  return result;
}

int
cmdline_parser (int argc, char **argv, struct gengetopt_args_info *args_info)
{
  return cmdline_parser2 (argc, argv, args_info, 0, 1, 1);
}

int
cmdline_parser_ext (int argc, char **argv, struct gengetopt_args_info *args_info,
                   struct cmdline_parser_params *params)
{
  int result;
  result = cmdline_parser_internal (argc, argv, args_info, params, 0);

  if (result == EXIT_FAILURE)
    {
      cmdline_parser_free (args_info);
      exit (EXIT_FAILURE);
    }
  
  return result;
}

int
cmdline_parser2 (int argc, char **argv, struct gengetopt_args_info *args_info, int override, int initialize, int check_required)
{
  int result;
  struct cmdline_parser_params params;
  
  params.override = override;
  params.initialize = initialize;
  params.check_required = check_required;
  params.check_ambiguity = 0;
  params.print_errors = 1;

  result = cmdline_parser_internal (argc, argv, args_info, &params, 0);

  if (result == EXIT_FAILURE)
    {
      cmdline_parser_free (args_info);
      exit (EXIT_FAILURE);
    }
  
  return result;
}

int
cmdline_parser_required (struct gengetopt_args_info *args_info, const char *prog_name)
{
  int result = EXIT_SUCCESS;

  if (cmdline_parser_required2(args_info, prog_name, 0) > 0)
    result = EXIT_FAILURE;

  if (result == EXIT_FAILURE)
    {
      cmdline_parser_free (args_info);
      exit (EXIT_FAILURE);
    }
  
  return result;
}

int
cmdline_parser_required2 (struct gengetopt_args_info *args_info, const char *prog_name, const char *additional_error)
{
  int error_occurred = 0;
  FIX_UNUSED (additional_error);

  /* checks for required options */
  
  /* checks for dependences among options */
  if (args_info->bits_given && ! args_info->genkey_given)
    {
      fprintf (stderr, "%s: '--bits' ('-b') option depends on option 'genkey'%s\n", prog_name, (additional_error ? additional_error : ""));
      error_occurred = 1;
    }
  if (args_info->show_given && ! args_info->keyfile_given)
    {
      fprintf (stderr, "%s: '--show' ('-w') option depends on option 'keyfile'%s\n", prog_name, (additional_error ? additional_error : ""));
      error_occurred = 1;
    }
  if (args_info->noaes_given && ! args_info->genkey_given)
    {
      fprintf (stderr, "%s: '--noaes' ('-n') option depends on option 'genkey'%s\n", prog_name, (additional_error ? additional_error : ""));
      error_occurred = 1;
    }

  return error_occurred;
}


static char *package_name = 0;

/**
 * @brief updates an option
 * @param field the generic pointer to the field to update
 * @param orig_field the pointer to the orig field
 * @param field_given the pointer to the number of occurrence of this option
 * @param prev_given the pointer to the number of occurrence already seen
 * @param value the argument for this option (if null no arg was specified)
 * @param possible_values the possible values for this option (if specified)
 * @param default_value the default value (in case the option only accepts fixed values)
 * @param arg_type the type of this option
 * @param check_ambiguity @see cmdline_parser_params.check_ambiguity
 * @param override @see cmdline_parser_params.override
 * @param no_free whether to free a possible previous value
 * @param multiple_option whether this is a multiple option
 * @param long_opt the corresponding long option
 * @param short_opt the corresponding short option (or '-' if none)
 * @param additional_error possible further error specification
 */
static
int update_arg(void *field, char **orig_field,
               unsigned int *field_given, unsigned int *prev_given, 
               char *value, const char *possible_values[],
               const char *default_value,
               cmdline_parser_arg_type arg_type,
               int check_ambiguity, int override,
               int no_free, int multiple_option,
               const char *long_opt, char short_opt,
               const char *additional_error)
{
  char *stop_char = 0;
  const char *val = value;
  int found;
  char **string_field;
  FIX_UNUSED (field);

  stop_char = 0;
  found = 0;

  if (!multiple_option && prev_given && (*prev_given || (check_ambiguity && *field_given)))
    {
      if (short_opt != '-')
        fprintf (stderr, "%s: `--%s' (`-%c') option given more than once%s\n", 
               package_name, long_opt, short_opt,
               (additional_error ? additional_error : ""));
      else
        fprintf (stderr, "%s: `--%s' option given more than once%s\n", 
               package_name, long_opt,
               (additional_error ? additional_error : ""));
      return 1; /* failure */
    }

  FIX_UNUSED (default_value);
    
  if (field_given && *field_given && ! override)
    return 0;
  if (prev_given)
    (*prev_given)++;
  if (field_given)
    (*field_given)++;
  if (possible_values)
    val = possible_values[found];

  switch(arg_type) {
  case ARG_FLAG:
    *((int *)field) = !*((int *)field);
    break;
  case ARG_INT:
    if (val) *((int *)field) = strtol (val, &stop_char, 0);
    break;
  case ARG_STRING:
    if (val) {
      string_field = (char **)field;
      if (!no_free && *string_field)
        free (*string_field); /* free previous string */
      *string_field = gengetopt_strdup (val);
    }
    break;
  default:
    break;
  };

  /* check numeric conversion */
  switch(arg_type) {
  case ARG_INT:
    if (val && !(stop_char && *stop_char == '\0')) {
      fprintf(stderr, "%s: invalid numeric value: %s\n", package_name, val);
      return 1; /* failure */
    }
    break;
  default:
    ;
  };

  /* store the original value */
  switch(arg_type) {
  case ARG_NO:
  case ARG_FLAG:
    break;
  default:
    if (value && orig_field) {
      if (no_free) {
        *orig_field = value;
      } else {
        if (*orig_field)
          free (*orig_field); /* free previous string */
        *orig_field = gengetopt_strdup (value);
      }
    }
  };

  return 0; /* OK */
}


int
cmdline_parser_internal (
  int argc, char **argv, struct gengetopt_args_info *args_info,
                        struct cmdline_parser_params *params, const char *additional_error)
{
  int c;	/* Character of the parsed option.  */

  int error_occurred = 0;
  struct gengetopt_args_info local_args_info;
  
  int override;
  int initialize;
  int check_required;
  int check_ambiguity;
  
  package_name = argv[0];
  
  /* TODO: Why is this here? It is not used anywhere. */
  override = params->override;
  FIX_UNUSED(override);

  initialize = params->initialize;
  check_required = params->check_required;

  /* TODO: Why is this here? It is not used anywhere. */
  check_ambiguity = params->check_ambiguity;
  FIX_UNUSED(check_ambiguity);

  if (initialize)
    cmdline_parser_init (args_info);

  cmdline_parser_init (&local_args_info);

  optarg = 0;
  optind = 0;
  opterr = params->print_errors;
  optopt = '?';

  while (1)
    {
      int option_index = 0;

      static struct option long_options[] = {
        { "help",	0, NULL, 'h' },
        { "version",	0, NULL, 'V' },
        { "infile",	1, NULL, 'i' },
        { "outfile",	1, NULL, 'o' },
        { "encrypt",	0, NULL, 'e' },
        { "decrypt",	0, NULL, 'd' },
        { "genkey",	0, NULL, 'g' },
        { "bits",	1, NULL, 'b' },
        { "ascii",	0, NULL, 'a' },
        { "keyfile",	1, NULL, 'k' },
        { "show",	0, NULL, 'w' },
        { "noaes",	0, NULL, 'n' },
        { "encryptkey",	0, NULL, 'c' },
        { "decryptkey",	0, NULL, 'r' },
        { "sign",	0, NULL, 's' },
        { "verify",	0, NULL, 'v' },
        { 0,  0, 0, 0 }
      };

      c = getopt_long (argc, argv, "hVi:o:edgb:ak:wncrsv", long_options, &option_index);

      if (c == -1) break;	/* Exit from `while (1)' loop.  */

      switch (c)
        {
        case 'h':	/* Print help and exit.  */
          cmdline_parser_print_help ();
          cmdline_parser_free (&local_args_info);
          exit (EXIT_SUCCESS);

        case 'V':	/* Print version and exit.  */
          cmdline_parser_print_version ();
          cmdline_parser_free (&local_args_info);
          exit (EXIT_SUCCESS);

        case 'i':	/* File to encrypt or sign.  */
        
        
          if (update_arg( (void *)&(args_info->infile_arg), 
               &(args_info->infile_orig), &(args_info->infile_given),
              &(local_args_info.infile_given), optarg, 0, 0, ARG_STRING,
              check_ambiguity, override, 0, 0,
              "infile", 'i',
              additional_error))
            goto failure;
        
          break;
        case 'o':	/* Name of the encrypted or the signed file.  */
        
        
          if (update_arg( (void *)&(args_info->outfile_arg), 
               &(args_info->outfile_orig), &(args_info->outfile_given),
              &(local_args_info.outfile_given), optarg, 0, 0, ARG_STRING,
              check_ambiguity, override, 0, 0,
              "outfile", 'o',
              additional_error))
            goto failure;
        
          break;
        case 'e':	/* Encrypts a file.  */
        
        
          if (update_arg((void *)&(args_info->encrypt_flag), 0, &(args_info->encrypt_given),
              &(local_args_info.encrypt_given), optarg, 0, 0, ARG_FLAG,
              check_ambiguity, override, 1, 0, "encrypt", 'e',
              additional_error))
            goto failure;
        
          break;
        case 'd':	/* Decrypts a file.  */
        
        
          if (update_arg((void *)&(args_info->decrypt_flag), 0, &(args_info->decrypt_given),
              &(local_args_info.decrypt_given), optarg, 0, 0, ARG_FLAG,
              check_ambiguity, override, 1, 0, "decrypt", 'd',
              additional_error))
            goto failure;
        
          break;
        case 'g':	/* Generates a pair of RSA keys.  */
        
        
          if (update_arg((void *)&(args_info->genkey_flag), 0, &(args_info->genkey_given),
              &(local_args_info.genkey_given), optarg, 0, 0, ARG_FLAG,
              check_ambiguity, override, 1, 0, "genkey", 'g',
              additional_error))
            goto failure;
        
          break;
        case 'b':	/* Bits of the generated RSA key.  */
        
        
          if (update_arg( (void *)&(args_info->bits_arg), 
               &(args_info->bits_orig), &(args_info->bits_given),
              &(local_args_info.bits_given), optarg, 0, "2048", ARG_INT,
              check_ambiguity, override, 0, 0,
              "bits", 'b',
              additional_error))
            goto failure;
        
          break;
        case 'a':	/* Writes the output file in ASCII format.  */
        
        
          if (update_arg((void *)&(args_info->ascii_flag), 0, &(args_info->ascii_given),
              &(local_args_info.ascii_given), optarg, 0, 0, ARG_FLAG,
              check_ambiguity, override, 1, 0, "ascii", 'a',
              additional_error))
            goto failure;
        
          break;
        case 'k':	/* File of the public or private RSA key.  */
        
        
          if (update_arg( (void *)&(args_info->keyfile_arg), 
               &(args_info->keyfile_orig), &(args_info->keyfile_given),
              &(local_args_info.keyfile_given), optarg, 0, 0, ARG_STRING,
              check_ambiguity, override, 0, 0,
              "keyfile", 'k',
              additional_error))
            goto failure;
        
          break;
        case 'w':	/* Shows a public or private RSA key.  */
        
        
          if (update_arg((void *)&(args_info->show_flag), 0, &(args_info->show_given),
              &(local_args_info.show_given), optarg, 0, 0, ARG_FLAG,
              check_ambiguity, override, 1, 0, "show", 'w',
              additional_error))
            goto failure;
        
          break;
        case 'n':	/* Saves the RSA private key unencrypted.  */
        
        
          if (update_arg((void *)&(args_info->noaes_flag), 0, &(args_info->noaes_given),
              &(local_args_info.noaes_given), optarg, 0, 0, ARG_FLAG,
              check_ambiguity, override, 1, 0, "noaes", 'n',
              additional_error))
            goto failure;
        
          break;
        case 'c':	/* Encrypts an RSA private key.  */
        
        
          if (update_arg((void *)&(args_info->encryptkey_flag), 0, &(args_info->encryptkey_given),
              &(local_args_info.encryptkey_given), optarg, 0, 0, ARG_FLAG,
              check_ambiguity, override, 1, 0, "encryptkey", 'c',
              additional_error))
            goto failure;
        
          break;
        case 'r':	/* Decrypts an RSA private key.  */
        
        
          if (update_arg((void *)&(args_info->decryptkey_flag), 0, &(args_info->decryptkey_given),
              &(local_args_info.decryptkey_given), optarg, 0, 0, ARG_FLAG,
              check_ambiguity, override, 1, 0, "decryptkey", 'r',
              additional_error))
            goto failure;
        
          break;
        case 's':	/* Signs a file.  */
        
        
          if (update_arg((void *)&(args_info->sign_flag), 0, &(args_info->sign_given),
              &(local_args_info.sign_given), optarg, 0, 0, ARG_FLAG,
              check_ambiguity, override, 1, 0, "sign", 's',
              additional_error))
            goto failure;
        
          break;
        case 'v':	/* Verify and extract a signed file.  */
        
        
          if (update_arg((void *)&(args_info->verify_flag), 0, &(args_info->verify_given),
              &(local_args_info.verify_given), optarg, 0, 0, ARG_FLAG,
              check_ambiguity, override, 1, 0, "verify", 'v',
              additional_error))
            goto failure;
        
          break;

        case 0:	/* Long option with no short option */
        case '?':	/* Invalid option.  */
          /* `getopt_long' already printed an error message.  */
          goto failure;

        default:	/* bug: option not considered.  */
          fprintf (stderr, "%s: option unknown: %c%s\n", CMDLINE_PARSER_PACKAGE, c, (additional_error ? additional_error : ""));
          abort ();
        } /* switch */
    } /* while */



  if (check_required)
    {
      error_occurred += cmdline_parser_required2 (args_info, argv[0], additional_error);
    }

  cmdline_parser_release (&local_args_info);

  if ( error_occurred )
    return (EXIT_FAILURE);

  return 0;

failure:
  
  cmdline_parser_release (&local_args_info);
  return (EXIT_FAILURE);
}
/* vim: set ft=c noet ts=8 sts=8 sw=8 tw=80 nojs spell : */
