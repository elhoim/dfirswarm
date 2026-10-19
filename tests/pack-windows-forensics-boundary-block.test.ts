/**
 * The SHARED BOUNDARY block of the windows-forensics tools, driven in-process: slice 1 of 3 of the carriers (the cases are in
 * tests/windows-boundary-block-cases.ts, which also says why they are three files).
 */
import { registerBlockCases } from "./windows-boundary-block-cases.ts";

await registerBlockCases(0, 3);
