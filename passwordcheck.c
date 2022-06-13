/*-------------------------------------------------------------------------
 * Luckyness
 * 20191202
 * 在源代码上修改自用，配置pg密码必须包含特殊字符
 * pg版本11.4
 * 使用方式：
 * 替换目录 ../postgresql-11.4/contrib/passwordcheck 下的 passwordcheck.c
 * 编译安装 make && make install
 * postgresql配置文件内修改 (postgresql.conf)
 * shared_preload_libraries = 'passwordcheck'
 * passwordcheck.level = 'true'
 *-------------------------------------------------------------------------
 */
/*-------------------------------------------------------------------------
 *
 * passwordcheck.c
 *
 *
 * Copyright (c) 2009-2018, PostgreSQL Global Development Group
 *
 * Author: Laurenz Albe <laurenz.albe@wien.gv.at>
 *
 * IDENTIFICATION
 *	  contrib/passwordcheck/passwordcheck.c
 *
 *-------------------------------------------------------------------------
 */
#include "postgres.h"

#include <ctype.h>

#ifdef USE_CRACKLIB
#include <crack.h>
#endif

#include "commands/user.h"
#include "libpq/crypt.h"
#include "fmgr.h"
/* 引入扩展 */
#include "utils/guc.h"


PG_MODULE_MAGIC;

/* 
 * 配置文件内passwordcheck.level='true' 为需要特殊字符 
 * passwordcheck.level='false' 为只需要英文和数字
 */
static bool passwordcheck_level = false;


/* passwords shorter than this will be rejected */
#define MIN_PWD_LENGTH 8

extern void _PG_init(void);

/*
 * check_password
 *
 * performs checks on an encrypted or unencrypted password
 * ereport's if not acceptable
 *
 * username: name of role being created or changed
 * password: new password (possibly already encrypted)
 * password_type: PASSWORD_TYPE_* code, to indicate if the password is
 *			in plaintext or encrypted form.
 * validuntil_time: password expiration time, as a timestamptz Datum
 * validuntil_null: true if password expiration time is NULL
 *
 * This sample implementation doesn't pay any attention to the password
 * expiration time, but you might wish to insist that it be non-null and
 * not too far in the future.
 */
static void

check_password(const char *username,
			   const char *shadow_pass,
			   PasswordType password_type,
			   Datum validuntil_time,
			   bool validuntil_null)
{
	if (password_type != PASSWORD_TYPE_PLAINTEXT)
	{
		/*
		 * Unfortunately we cannot perform exhaustive checks on encrypted
		 * passwords - we are restricted to guessing. (Alternatively, we could
		 * insist on the password being presented non-encrypted, but that has
		 * its own security disadvantages.)
		 *
		 * We only check for username = password.
		 */
		char	   *logdetail;

		if (plain_crypt_verify(username, shadow_pass, username, &logdetail) == STATUS_OK)
			ereport(ERROR,
					(errcode(ERRCODE_INVALID_PARAMETER_VALUE),
					 errmsg("password must not equal user name")));
	}
	else
	{
		/*
		 * For unencrypted passwords we can perform better checks
		 */
		const char *password = shadow_pass;
		int			pwdlen = strlen(password);
		int			i;
		/*                 bool            pwd_has_letter,*/
		bool		
					pwd_has_number,pwd_has_special,pwd_has_letter;

		/* enforce minimum length */
		if (pwdlen < MIN_PWD_LENGTH)
			ereport(ERROR,
					(errcode(ERRCODE_INVALID_PARAMETER_VALUE),
					 errmsg("password is too short")));

		/* check if the password contains the username */
		if (strstr(password, username))
			ereport(ERROR,
					(errcode(ERRCODE_INVALID_PARAMETER_VALUE),
					 errmsg("password must not contain user name")));

		if(passwordcheck_level)
		{
			/* check if the password contains both letters and number and specialchar */
			pwd_has_number = false;
			pwd_has_special = false;
			pwd_has_letter = false;
			for (i = 0; i < pwdlen; i++)
			{
				if (isalpha((unsigned char) password[i]))
					pwd_has_letter = true;
				else if (isdigit((unsigned char) password[i]))
					pwd_has_number = true;
				else
					pwd_has_special = true;
			}
			if (!pwd_has_number || !pwd_has_letter || !pwd_has_special)
				ereport(ERROR,
						(errcode(ERRCODE_INVALID_PARAMETER_VALUE),
						errmsg("password must contain both letters and number and specialchar")));
		}
		else
		{
			/* check if the password contains both letters and non-letters */
			pwd_has_letter = false;
			pwd_has_number = false;
			for (i = 0; i < pwdlen; i++)
			{
				if (isalpha((unsigned char) password[i]))
					pwd_has_letter = true;
				else
					pwd_has_number = true;
			}
			if (!pwd_has_letter || !pwd_has_number)
				ereport(ERROR,
						(errcode(ERRCODE_INVALID_PARAMETER_VALUE),
						errmsg("password must contain both letters and nonletters")));
		}

#ifdef USE_CRACKLIB
		/* call cracklib to check password */
		if (FascistCheck(password, CRACKLIB_DICTPATH))
			ereport(ERROR,
					(errcode(ERRCODE_INVALID_PARAMETER_VALUE),
					 errmsg("password is easily cracked")));
#endif
	}

	/* all checks passed, password is ok */
}

/*
 * Module initialization function
 */
void
_PG_init(void)
{
	/* 密码级别参数 */
	DefineCustomBoolVariable(
		"passwordcheck.level",
		gettext_noop("passwordcheck_level true: Password must contain leter, number, special characters;false : Password must contain leter, special characters"),
		NULL,
		&passwordcheck_level,
		false,
		PGC_POSTMASTER,
		GUC_SUPERUSER_ONLY,
		NULL, NULL, NULL);

	/* activate password checks when the module is loaded */
	check_password_hook = check_password;
}
