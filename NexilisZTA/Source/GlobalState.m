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
#import <stdatomic.h>

/*
 * Written from the pre-main native chain, the periodic sweep, the recovery re-check and the
 * verification chain on the main queue; read from all of them and from AppAttestService's own
 * guards. A plain static gives no guarantee that a write on one thread is ever seen by another,
 * which for a gate means a stage can be skipped or repeated.
 */
static _Atomic(int32_t) g_state = NX_STATE_IDLE;

int32_t stateGet(void) { return atomic_load(&g_state); }
void stateSet(int32_t state) { atomic_store(&g_state, state); }
