// SPDX-License-Identifier: MIT
pragma solidity >=0.4.22 <0.9.0;

import "@openzeppelin/contracts/access/Ownable.sol";

/**
 * A SafeOwnable contract is pretty much the same as the classical
 * ownable one, but the ownership cannot be renounced.
 */
abstract contract SafeOwnable is Ownable {
    function renounceOwnership() public override onlyOwner {
        revert("SafeOwnable: ownership cannot be renounced");
    }
}
