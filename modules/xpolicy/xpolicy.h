#ifndef XPOLICY_H
#define XPOLICY_H

// 1 = this xkeys label may be used now (always true when no app is running)
int xp_key_allowed(const char *label);

#endif