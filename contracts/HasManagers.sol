pragma solidity >=0.4.22 <0.9.0;

import "@openzeppelin/contracts/utils/Context.sol";

/**
 * Admins are described here. Here, the admins are meant to be created and
 * frozen (a different kind of "destroyed", soft and reversible). No role
 * is described here for the admins.
 */
abstract contract HasManagers is Context {
    /**
     * This event tells that a manager was added.
     */
    event ManagerAdded(address indexed who, string name);

    /**
     * This event tells that a manager was removed.
     */
    event ManagerRemoved(address indexed who);

    /**
     * The registered admins. Those admins are first created and, perhaps,
     * later modified, enabled or disabled. These entries exist on their
     * own, but tied to their underlying address.
     */
    struct Manager {
        /**
         * Tells when was this admin created. A value of 0 means this record
         * does not actually exist when retrieving it from the admins mapping.
         */
        uint256 createdAt;
        /**
         * Tells whether an admin can operate over the whole platform they
         * are assigned to manage. When this flag is false, even if the admin
         * record exists, the admin cannot operate over their existing records
         * or claim new ones from an assigned TLD. They will STILL own their
         * domains unless they are explicitly removed from them.
         *
         * By default, on creation, this flag is true.
         *
         * This flag will be used instead of deletion, actually. If the address
         * is lost, the contract owner may move this record to a new address,
         * in order to not need to freeze this record and add a new one. To
         * have this entry frozen, forbids the admin of ANY action, as if it
         * was never an admin in first place. "Frozen" means !enabled.
         */
        bool enabled;
        /**
         * A name, or a nickname, may be provided to describe this admin account.
         * This field is not mandatory, and it is OK to leave it empty ("").
         */
        string name;
    }

    // Notes: Derived classes will make use of the managers member
    //        to know whether the sender is allowed, or not, to
    //        perform certain action(s).

    /**
     * The mapping of admins can be publicly retrieved. Nothing specified (e.g.
     * TLDs in charge or registered domains).
     */
    mapping(address => Manager) public managers;

    /**
     * The list of admin addresses, to be enumerated.
     */
    address[] public managersList;

    /**
     * The count of registered managers, including the disabled ones.
     */
    uint256 public managersCount;

    /**
     * Adds a manager with no name or, if present, respecting the previous name.
     * The manager record gets enabled.
     */
    function _addManager(address who) internal {
        Manager storage record = managers[who];
        if (record.createdAt != 0) {
            record.enabled = true;
            emit ManagerAdded(who, record.name);
        } else {
            managers[who] = Manager({createdAt: block.timestamp, enabled: true});
            managersList.push(who);
            emit ManagerAdded(who, "");
        }
    }

    /**
     * Adds a manager with a name or, if present, respecting the previous name.
     * The manager record gets enabled.
     */
    function _addManager(address who, string memory name) internal {
        Manager storage record = managers[who];
        if (record.createdAt != 0) {
            record.enabled = true;
            emit ManagerAdded(who, record.name);
        } else {
            managers[who] = Manager({createdAt: block.timestamp, enabled: true, name: name});
            managersList.push(who);
            emit ManagerAdded(who, name);
        }
    }

    /**
     * Removes a manager record, if present. It actually does not remove it but
     * disables it instead.
     */
    function _removeManager(address who) internal {
        Manager storage record = managers[who];
        if (manager.createdAt != 0) {
            manager.enabled = false;
        }
        emit ManagerRemoved(who);
    }
}
