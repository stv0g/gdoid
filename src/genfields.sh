# $Id: genfields.sh,v 1.4 2005/10/11 17:57:36 bew Exp $
# $Source: /nfs/cscbz/gdoi/gdoicvs/gdoi/src/genfields.sh,v $

#	$OpenBSD: genfields.sh,v 1.6 2001/01/27 12:03:32 niklas Exp $
#	$EOM: genfields.sh,v 1.5 1999/04/02 01:15:55 niklas Exp $

# 
# The license applies to all software incorporated in the "Cisco GDOI reference
# implementation" except for those portions incorporating third party software 
# specifically identified as being licensed under separate license. 
#  
#  
# The Cisco Systems Public Software License, Version 1.0 
# Copyright (c) 2001 Cisco Systems, Inc. All rights reserved.
# Subject to the following terms and conditions, Cisco Systems, Inc., 
# hereby grants you a worldwide, royalty-free, nonexclusive, license, 
# subject to third party intellectual property claims, to create 
# derivative works of the Licensed Code and to reproduce, display, 
# perform, sublicense, distribute such Licensed Code and derivative works. 
# All rights not expressly granted herein are reserved. 
# 1.      Redistributions of source code must retain the above 
# copyright notice, this list of conditions and the following 
# disclaimer.
# 2.      Redistributions in binary form must reproduce the above 
# copyright notice, this list of conditions and the following 
# disclaimer in the documentation and/or other materials 
# provided with the distribution.  
# 3.      The names Cisco and "Cisco GDOI reference implementation" must not 
# be used to endorse or promote products derived from this software without 
# prior written permission. For written permission, please contact 
# opensource@cisco.com.
# 4.      Products derived from this software may not be called 
# "Cisco" or "Cisco GDOI reference implementation", nor may "Cisco" or 
# "Cisco GDOI reference implementation" appear in 
# their name, without prior written permission of Cisco Systems, Inc.
# THIS SOFTWARE IS PROVIDED "AS IS" AND ANY EXPRESSED OR IMPLIED 
# WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED 
# WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR 
# PURPOSE, TITLE AND NON-INFRINGEMENT ARE DISCLAIMED. IN NO EVENT 
# SHALL CISCO SYSTEMS, INC. OR ITS CONTRIBUTORS BE LIABLE FOR ANY 
# INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL 
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF 
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR 
# BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF 
# LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT 
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF 
# THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF 
# SUCH DAMAGE. THIS LIMITATION OF LIABILITY SHALL NOT APPLY TO 
# LIABILITY FOR DEATH OR PERSONAL INJURY RESULTING FROM SUCH 
# PARTY'S NEGLIGENCE TO THE EXTENT APPLICABLE LAW PROHIBITS SUCH 
# LIMITATION. SOME JURISDICTIONS DO NOT ALLOW THE EXCLUSION OR 
# LIMITATION OF INCIDENTAL OR CONSEQUENTIAL DAMAGES, SO THAT 
# EXCLUSION AND LIMITATION MAY NOT APPLY TO YOU. FURTHER, YOU 
# AGREE THAT IN NO EVENT WILL CISCO'S LIABILITY UNDER OR RELATED TO 
# THIS AGREEMENT EXCEED AMOUNT FIVE THOUSAND DOLLARS (US) 
# (US$5,000). 
#  
# ====================================================================
# This software consists of voluntary contributions made by Cisco Systems, 
# Inc. and many individuals on behalf of Cisco Systems, Inc. For more 
# information on Cisco Systems, Inc., please see <http://www.cisco.com/>.
#
# This product includes software developed by Ericsson Radio Systems.
#

#
# Copyright (c) 1998, 1999, 2001 Niklas Hallqvist.  All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
# 3. All advertising materials mentioning features or use of this software
#    must display the following acknowledgement:
#	This product includes software developed by Ericsson Radio Systems.
# 4. The name of the author may not be used to endorse or promote products
#    derived from this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
# IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
# OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
# IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
# NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
# DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
# THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
# THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#

#
# This code was written under funding by Ericsson Radio Systems.
#

base=`basename $1`
upcased_name=`echo $base |tr a-z A-Z`

awk=${AWK:-awk}

locase_function='function locase (str) {
  cmd = "echo " str " |tr A-Z a-z"
  cmd | getline retval;
  close (cmd);
  return retval;
}'

$awk " 
$locase_function
"'
BEGIN {
  print "/* DO NOT EDIT-- this file is automatically generated.  */\n"
  print "#ifndef _'$upcased_name'_H_"
  print "#define _'$upcased_name'_H_\n"

  print "#include \"sysdep.h\"\n"
  print "#include \"field.h\"\n"

  print "struct constant_map;\n"
}

/^#/ {
  next
}

/^\./ {
  printf ("#define %s_SZ %d\n", prefix, off)
  size[prefix] = off
  next
}

/^[^ 	]/ {
  prefix = $1
  printf ("extern struct field %s_fld[];\n\n", locase(prefix));
  if ($3)
    {
      off = size[$3]
    }
  else
    {
      off = 0
    }
  i = 0
  next
}

/^[ 	]/ && $1 {
  printf ("#define %s_%s_OFF %d\n", prefix, $1, off)
  if ($3)
    {
      printf ("#define %s_%s_LEN %d\n", prefix, $1, $3)
    }
  if ($4)
    {
      printf ("extern struct constant_map *%s_%s_maps[];\n", locase(prefix),
              locase($1))
    }
  if ($2 == "raw")
    {
      printf ("#define GET_%s_%s(buf, val) ", prefix, $1)
      printf ("field_get_raw (%s_fld + %d, buf, val)\n", locase(prefix), i)
      printf ("#define SET_%s_%s(buf, val) ", prefix, $1)
      printf ("field_set_raw (%s_fld + %d, buf, val)\n", locase(prefix), i)
    }
  else
    {
      printf ("#define GET_%s_%s(buf) field_get_num (%s_fld + %d, buf)\n",
              prefix, $1, locase(prefix), i)
      printf ("#define SET_%s_%s(buf, val) ", prefix, $1)
      printf ("field_set_num (%s_fld + %d, buf, val)\n", locase(prefix), i)
    }
  off += $3
  i++
  next
}

{
    print
}

END {
  printf ("\n")
  print "#endif /* _'$upcased_name'_H_ */"
}
' <$1.fld >$base.h

$awk "
$locase_function
"'
BEGIN {
  print "/* DO NOT EDIT-- this file is automatically generated.  */\n"
  print "#include \"sysdep.h\"\n"
  print "#include \"constants.h\""
  print "#include \"field.h\""
  print "#include \"'$base'.h\""
  print "#include \"isakmp_num.h\""
  print "#include \"ipsec_num.h\"\n"
  print "#include \"gdoi_num.h\"\n"
}

/^#/ {
  next
}

/^\./ {
  print "  { 0, 0, 0, 0, 0 }\n};\n"
  size[prefix] = off
  for (map in maps)
    {
      printf ("struct constant_map *%s_%s_maps[] = { ", locase(prefix),
             locase(map))
      printf ("%s,0 };\n", maps[map])
    }
  next
}

/^[^ 	]/ {
  prefix = $1
  printf ("struct field %s_fld[] = {\n", locase(prefix))
  if ($3)
    {
      off = size[$3]
    }
  else
    {
      off = 0
    }
  delete maps
  next
}

/^[ 	]/ && $1 {
  if ($4)
    {
      maps_name = locase(prefix)"_"locase($1)"_maps"
      maps[$1] = $4
    }
  else
    {
      maps_name = "0"
    }
  printf ("  { \"%s\", %d, %d, %s, %s }, \n", $1, off, $3, $2, maps_name)
  off += $3
  next
}

{
  print
}
' <$1.fld >$base.c
