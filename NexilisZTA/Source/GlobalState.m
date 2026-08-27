//
//  GlobalState.m
//  OneApp
//
//  Created by Qindi on 01/07/26.
//
#import "GlobalState.h"
#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <os/log.h>
#import <signal.h>
#import <stdlib.h>

static int32_t g_state = NX_STATE_IDLE;

int32_t stateGet(void) { return g_state; }
void stateSet(int32_t state) { g_state = state; }
