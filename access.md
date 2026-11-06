
Access is re-imagined for the entire system, with refactors done at all relevant bottlenecks.

## Room membership and the ability to post

In a typical design such as Matrix, the access control is tracked as a mapping updated by a DAG-CRDT style state machine, where user ID maps to a capability value.

This bottleneck can be simplified to *any valid ZK proof proving adequate rights to post*, such as a merkle-membership proof over a computed room member set, which is anonymous. 

## Inbox-control

Inbox is regarded as a scarce resource and subject to user control.

Typical apps dont have a good way to handle this problem. User inbox gets spammed. Then, either, excessive CAPTCHA is used, or in Matrix's case, homeserver owners become de facto nanny of users' inboxes.

In the most general case, applicants can post to a user's inbox with a ZK argument of sufficient value, or at least argument of non-abuse.

Inbox mostly contains room invites.

## Scalable and fair path freedom

The goal of this engineering, is not to create an all encompassing reputation system right here in ZK. 

Say, we have an anonymous membership proof system here. Path freedom is the fact that users may have many many ways to obtain a membership. The old method is to use a publickey-set, but it introduces unnecessary cost when the churn is high. 

Good social systems enable path-freedom. 

For DDOS control, most people use IP quality ranking systems. This causes IPs to be hoarded and treated as assets. Path freedom exists because good IPs can be purchased by money, but this is inefficient to its intended anti-abuse goals. Rich and powerful attackers can still use hoarded IP pools to carry out attacks.