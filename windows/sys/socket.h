#include <winsock2.h>
#include <ws2tcpip.h>
#undef HAVE_NETLINK

typedef unsigned short sa_family_t;

#ifdef __CHECKER__ 
#if !defined(_WIN32)
#define __bitwise__ __attribute__((bitwise))
#endif
#else
#ifndef __bitwise__
#define __bitwise__
#endif
#endif
#ifdef __CHECK_ENDIAN__
#ifndef __bitwise
#define __bitwise __bitwise__
#endif
#else
#ifndef __bitwise
#define __bitwise
#endif
#endif


typedef unsigned short __bitwise __le16;
typedef unsigned short __bitwise __be16;

typedef unsigned int __bitwise __le32;
typedef unsigned int __bitwise __be32;

typedef unsigned long long __bitwise __le64;
typedef unsigned long long __bitwise __be64;


//typedef unsigned int socklen_t;