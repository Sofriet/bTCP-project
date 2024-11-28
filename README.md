# bTCP-project from Networks and Security 2023 (at Radboud)
Created sending and receiving transport-layer code from given template
<br> with Slavi Ivanov
Feedback:
The provided code passes none of the tests, because of the following bug: in recv, the length of the segment is not taken into account when extending 'data'.
Having fixed this, and with some tweaks to the way the test framework is ran, the code only passes tests 1_1 (ideal), 2_1 (bitflips), 3_1 (duplication)
