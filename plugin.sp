#pragma semicolon 1

#include <sourcemod>

public Plugin:myinfo = {
	name        = "",
	author      = "",
	description = "",
	version     = "0.0.0",
	url         = ""
};

public OnPluginStart()
{
	PrintToServer("Hello, World!");
}

