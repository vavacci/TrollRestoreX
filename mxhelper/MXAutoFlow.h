#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>

@interface MXAutoFlow : NSObject

// Runs the auto-install state machine if not already DONE.
// Safe to call multiple times. Hides vc.view and shows an overlay while running.
+ (void)runOnceWithViewController:(UIViewController*)vc;

@end
