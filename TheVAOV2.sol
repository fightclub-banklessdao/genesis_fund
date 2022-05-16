// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.2;

import "@openzeppelin/contracts/utils/math/SafeMath.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/utils/Context.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";

// create the vao, setting the global variables, set the admin fee, set the first member as the creator
// member adding - create a proposal applicant (which will actually get the funds + shares) proposer (which is the one giving the money) 
// (set how many shares + funds they want, how much they are going to stake - put that money in escrow)
// member adding - sponsor proposal (sponsor has to pay a fee)
// member adding - voting
// member adding - processing (check whether proposal succeeded) If it succeeded, assign share + funds to member
// investment - create a proposal, applicant is the one receiving the funds from the vao. 
// investment - sponsor proposal (sponsor has to pay a fee)
// investment - voting
// investment - processing (check whether proposal succeeded) If it succeeded, give the proposed funds to applicant
// kicking - create a proposal, applicant is the one being kicked
// ...
// whitelisting - create a proposal, token to be whitelisted (can be used for staking + funding)
// ragequiting - can only quit if current vote you voted yes on is processed
// withdrawing/collecting tokens, etc

contract VAO is ReentrancyGuard, Ownable {
    using SafeMath for uint256;

    /***************
    GLOBAL CONSTANTS
    ***************/
    uint256 public periodDuration; // default = 17280 = 4.8 hours in seconds (5 periods per day)
    uint256 public votingPeriodLength; // default = 35 periods (7 days)
    uint256 public gracePeriodLength; // default = 35 periods (7 days)
    uint256 public proposalDeposit; // default = 10 ETH (~$1,000 worth of ETH at contract deployment)
    uint256 public dilutionBound; // default = 3 - maximum multiplier a YES voter will be obligated to pay in case of mass ragequit
    uint256 public processingReward; // default = 0.1 - amount of ETH to give to whoever processes a proposal
    uint256 public creationTime; // needed to determine the current period

    address public depositToken; // deposit token contract reference; default = wETH
    /******
     AdminFee - VAO exclusive
     *********/
    uint256 public constant paymentPeriod = 90 days; //90 days; - 1 day is for test only!
    uint256 public lastPaymentTime; // this will set as 'now' in construtor = creationTime;
    address public vaoFundAddress; // This field MUST be set in constructor or set to default to creator here.
    uint256 public adminFeeDenominator = 200; // initial denominator

    // ***************
    // EVENTS
    // ***************
    event CreationComplete(address indexed creator, address[] tokens, uint256 creationTime, uint256 periodDuration, uint256 votingPeriodLength, uint256 gracePeriodLength, uint256 proposalDeposit, uint256 dilutionBound, uint256 processingReward);
    event SubmitProposal(address indexed applicant, uint256 sharesRequested, uint256 fundsRequested, uint256 stakeeOffered, address stakeeToken, uint256 paymentRequested, address paymentToken, string details, bool[6] flags, uint256 proposalId, address indexed delegateKey, address indexed memberAddress);
    event SponsorProposal(address indexed delegateKey, address indexed memberAddress, uint256 proposalId, uint256 proposalIndex, uint256 startingPeriod);
    event SubmitVote(uint256 proposalId, uint256 indexed proposalIndex, address indexed delegateKey, address indexed memberAddress, uint8 uintVote);
    event ProcessProposal(uint256 indexed proposalIndex, uint256 indexed proposalId, bool didPass);
    event ProcessWhitelistProposal(uint256 indexed proposalIndex, uint256 indexed proposalId, bool didPass);
    event ProcessVAOKickProposal(uint256 indexed proposalIndex, uint256 indexed proposalId, bool didPass);
    event Ragequit(address indexed memberAddress, uint256 sharesToBurn, uint256 fundsToBurn);
    event TokensCollected(address indexed token, uint256 amountToCollect);
    event CancelProposal(uint256 indexed proposalId, address applicantAddress);
    event UpdateDelegateKey(address indexed memberAddress, address newDelegateKey);
    event Withdraw(address indexed memberAddress, address token, uint256 amount);

    // *******************
    // INTERNAL ACCOUNTING
    // *******************
    uint256 public proposalCount = 0; // total proposals submitted
    uint256 public totalShares = 0; // total shares across all members
    uint256 public totalFunds = 0; // total funds across all members

    uint256 public totalBankTokens = 0; // total tokens with non-zero balance in bank

    address public constant BANK = address(0x1337);
    address public constant ESCROW = address(0xf047);
    address public constant TOTAL = address(0x7073);
    mapping (address => mapping(address => uint256)) public userTokenBalances; // userTokenBalances[userAddress][tokenAddress]

    enum Vote {
        Null, // default value, counted as abstention
        Yes,
        No
    }

    struct Member {
        address delegateKey; // the key responsible for submitting proposals and voting - defaults to member address unless updated
        uint256 shares; // the # of voting shares assigned to this member
        uint256 funds; // the funds amount available to this member (combined with shares on ragequit)
        bool exists; // always true once a member has been created
        uint256 highestIndexYesVote; // highest proposal index # on which the member voted YES
        uint256 banned; // set to proposalIndex of a passing vao kick proposal for this member, prevents voting on and sponsoring proposals
    }

    struct Proposal {
        // applicant - the applicant who wishes to become a member - this key will be used for withdrawals (doubles as vao kick target for kick proposals)
        // proposer - the account that submitted the proposal (can be non-member)
        // sponsor - the member that sponsored the proposal (moving it into the queue)
        address[3] proposalAddresses; // [applicant, proposer, sponsor]
        uint256 sharesRequested; // the # of shares the applicant is requesting
        uint256 fundsRequested; // the amount of funds the applicant is requesting
        uint256 stakeOffered; // amount of tokens offered as stake
        address stakeToken; // stake token contract reference
        uint256 paymentRequested; // amount of tokens requested as payment
        address paymentToken; // payment token contract reference
        uint256 startingPeriod; // the period in which voting can start for this proposal
        uint256 yesVotes; // the total number of YES votes for this proposal
        uint256 noVotes; // the total number of NO votes for this proposal
        bool[6] flags; // [sponsored, processed, didPass, cancelled, whitelist, vaokick]
        string details; // proposal details - could be IPFS hash, plaintext, or JSON
        uint256 maxTotalSharesAndFundsAtYesVote; // the maximum # of total shares encountered at a yes vote on this proposal
        mapping(address => Vote) votesByMember; // the votes on this proposal by each member
    }

    mapping(address => bool) public tokenWhitelist;
    address[] public approvedTokens;

    mapping(address => bool) public proposedToWhitelist;
    mapping(address => bool) public proposedToKick;

    mapping(address => Member) public members;
    mapping(address => address) public memberAddressByDelegateKey;

    mapping(uint256 => Proposal) public proposals;

    uint256[] public proposalQueue;

    modifier onlyMember {
        require(members[msg.sender].shares > 0 || members[msg.sender].funds > 0, "not a member");
        _;
    }

    modifier onlyShareholder {
        require(members[msg.sender].shares > 0, "not a shareholder");
        _;
    }

    modifier onlyDelegate {
        require(members[memberAddressByDelegateKey[msg.sender]].shares > 0, "not a delegate");
        _;
    }

    constructor(
        address _creator,
        address[] memory _approvedTokens,
        uint256 _periodDuration,
        uint256 _votingPeriodLength,
        uint256 _gracePeriodLength,
        uint256 _proposalDeposit,
        uint256 _dilutionBound,
        uint256 _processingReward,
        address _vaoFundAddress
    ) {
        require(_creator != address(0), "creator = 0");
        require(_periodDuration > 0, "_periodDuration = 0");
        require(_votingPeriodLength > 0, "_votingPeriodLength = 0");
        require(_dilutionBound > 0, "_dilutionBound = 0");
        require(_approvedTokens.length > 0, "approved token = 0");
        require(_proposalDeposit >= _processingReward, "_proposalDeposit < _processingReward");
        require(_vaoFundAddress != address(0), "vaoFundAddress = 0");
        depositToken = _approvedTokens[0];
        // NOTE: move event up here, avoid stack too deep if too many approved tokens
        emit CreationComplete(_creator, _approvedTokens, block.timestamp, _periodDuration, _votingPeriodLength, _gracePeriodLength, _proposalDeposit, _dilutionBound, _processingReward);


        for (uint256 i = 0; i < _approvedTokens.length; i++) {
            require(_approvedTokens[i] != address(0), "_approvedToken = 0");
            require(!tokenWhitelist[_approvedTokens[i]], "duplicate approved token");
            tokenWhitelist[_approvedTokens[i]] = true;
            approvedTokens.push(_approvedTokens[i]);
        }

        periodDuration = _periodDuration;
        votingPeriodLength = _votingPeriodLength;
        gracePeriodLength = _gracePeriodLength;
        proposalDeposit = _proposalDeposit;
        dilutionBound = _dilutionBound;
        processingReward = _processingReward;

        creationTime = block.timestamp;
        vaoFundAddress = _vaoFundAddress; // VAO add on for adminFee
        lastPaymentTime = block.timestamp;  // VAO add on adminFee
        members[_creator] = Member(_creator, 1, 0, true, 0, 0);
        memberAddressByDelegateKey[_creator] = _creator;
        totalShares = 1;
       
    }
    
    /*******

    ADMIN FEE FUNCTION 
    setAdminFee can only be changed by Owner
    withdrawAdminFee can by be called by any ETH address

    ******/
    
    /// @dev Owner can change amount of adminFee and direction of funds 
    /// @param _adminFeeDenominator must be >= 200. Greater than 200, will equal 0.5% or less of assets.  
    /// @param _vaoFundAddress - where the Owner wants the funds to go. 

    function setAdminFee (uint256 _adminFeeDenominator, address _vaoFundAddress) public nonReentrant onlyOwner{
        require(_adminFeeDenominator >= 200, "< 200bps"); 
        adminFeeDenominator = _adminFeeDenominator; 
        vaoFundAddress = _vaoFundAddress;
    } //end of setAdminFee
    
    //can be called by an ETH Address
    function withdrawAdminFee () public nonReentrant {
       
        require (block.timestamp >= lastPaymentTime.add(paymentPeriod), "< 90 days withdrawal");
        lastPaymentTime = block.timestamp;
        // local variables to save gas by reading from storage only 1x
        uint256 denominator = adminFeeDenominator; 
        address recipient = vaoFundAddress;
        
        for (uint256 i = 0; i < approvedTokens.length; i++) {
            address token = approvedTokens[i];
            uint256 amount = userTokenBalances[BANK][token] / denominator;
            if (amount > 0) { // otherwise skip for efficiency, only tokens with a balance
               userTokenBalances[BANK][token] -= amount;
               userTokenBalances[recipient][token] += amount;
            }
        } 
        // Remove Event emit WithdrawAdminFee(vaoFundAddress,token, amount);
    } //end of withdrawAdminFee
    
    /*****************
    PROPOSAL FUNCTIONS
    *****************/
    function submitProposal(
        address applicant,
        uint256 sharesRequested,
        uint256 fundsRequested,
        uint256 stakeOffered,
        address stakeToken,
        uint256 paymentRequested,
        address paymentToken,
        string memory details
    ) public nonReentrant returns (uint256 proposalId) {
        require(tokenWhitelist[stakeToken], "stakeToken !whitelisted");
        require(tokenWhitelist[paymentToken], "payment !whitelisted");
        require(applicant != address(0), "applicant = 0");
        require(applicant != BANK && applicant != ESCROW && applicant != TOTAL, "address reserved");
        require(members[applicant].banned == 0, "proposal applicant !banned");

        // collect stake from proposer and store it in the VAO until the proposal is processed
        require(IERC20(stakeToken).transferFrom(msg.sender, address(this), stakeOffered), "stake token transfer failed");
        unsafeAddToBalance(ESCROW, stakeToken, stakeOffered);

        bool[6] memory flags; // [sponsored, processed, didPass, cancelled, whitelist, vaokick]

        _submitProposal(applicant, sharesRequested, fundsRequested, stakeOffered, stakeToken, paymentRequested, paymentToken, details, flags);
        return proposalCount - 1; // return proposalId - contracts calling submit might want it
    }

    function submitWhitelistProposal(address tokenToWhitelist, string memory details) public nonReentrant returns (uint256 proposalId) {
        require(tokenToWhitelist != address(0), "!token");
        require(!tokenWhitelist[tokenToWhitelist], "!whitelist");

        bool[6] memory flags; // [sponsored, processed, didPass, cancelled, whitelist, vaokick]
        flags[4] = true; // whitelist

        _submitProposal(address(0), 0, 0, 0, tokenToWhitelist, 0, address(0), details, flags);
        return proposalCount - 1;
    }

    function submitVAOKickProposal(address memberToKick, string memory details) public nonReentrant returns (uint256 proposalId) {
        Member memory member = members[memberToKick];

        require(member.shares > 0 || member.funds > 0, "!member");
        require(members[memberToKick].banned == 0, "member !banned");

        bool[6] memory flags; // [sponsored, processed, didPass, cancelled, whitelist, vaokick]
        flags[5] = true; // vaokick

        _submitProposal(memberToKick, 0, 0, 0, address(0), 0, address(0), details, flags);
        return proposalCount - 1;
    }

    function _submitProposal(
        address applicant,
        uint256 sharesRequested,
        uint256 fundsRequested,
        uint256 stakeOffered,
        address stakeToken,
        uint256 paymentRequested,
        address paymentToken,
        string memory details,
        bool[6] memory flags
    ) internal {
        Proposal storage proposal = proposals[proposalCount];
        proposal.proposalAddresses[0] = applicant;
        proposal.proposalAddresses[1] = msg.sender;
        proposal.proposalAddresses[2] = address(0);
        proposal.sharesRequested = sharesRequested;
        proposal.fundsRequested = fundsRequested;
        proposal.stakeOffered = stakeOffered;
        proposal.stakeToken = stakeToken;
        proposal.paymentRequested = paymentRequested;
        proposal.paymentToken = paymentToken;
        proposal.startingPeriod = 0;
        proposal.yesVotes = 0;
        proposal.noVotes = 0;
        proposal.flags = flags;
        proposal.details = details;
        proposal.maxTotalSharesAndFundsAtYesVote = 0;

        address memberAddress = memberAddressByDelegateKey[msg.sender];
        // NOTE: argument order matters, avoid stack too deep
        emit SubmitProposal(applicant, sharesRequested, fundsRequested, stakeOffered, stakeToken, paymentRequested, paymentToken, details, flags, proposalCount, msg.sender, memberAddress);
        proposalCount += 1;
    }

    function sponsorProposal(uint256 proposalId) public nonReentrant onlyDelegate {
        // collect proposal deposit from sponsor and store it in the VAO until the proposal is processed
        require(IERC20(depositToken).transferFrom(msg.sender, address(this), proposalDeposit), "proposal deposit token transfer failed");
        unsafeAddToBalance(ESCROW, depositToken, proposalDeposit);

        Proposal storage proposal = proposals[proposalId];

        require(proposal.proposalAddresses[1] != address(0), "proposal !proposed");
        require(!proposal.flags[0], "proposal sponsored");
        require(!proposal.flags[3], "proposal cancelled");
        require(members[proposal.proposalAddresses[0]].banned == 0, "applicant !banned");

        // whitelist proposal
        if (proposal.flags[4]) {
            require(!tokenWhitelist[address(proposal.stakeToken)], "!whitelist");
            require(!proposedToWhitelist[address(proposal.stakeToken)], "!proposed whitelist");
            proposedToWhitelist[address(proposal.stakeToken)] = true;

        // kick proposal
        } else if (proposal.flags[5]) {
            require(!proposedToKick[proposal.proposalAddresses[0]], "!proposed kick");
            proposedToKick[proposal.proposalAddresses[0]] = true;
        }

        // compute startingPeriod for proposal
        uint256 startingPeriod = max(
            getCurrentPeriod(),
            proposalQueue.length == 0 ? 0 : proposals[proposalQueue[proposalQueue.length.sub(1)]].startingPeriod
        ).add(1);

        proposal.startingPeriod = startingPeriod;

        address memberAddress = memberAddressByDelegateKey[msg.sender];
        proposal.proposalAddresses[2] = memberAddress;

        proposal.flags[0] = true; // sponsored

        // append proposal to the queue
        proposalQueue.push(proposalId);
        
        emit SponsorProposal(msg.sender, memberAddress, proposalId, proposalQueue.length.sub(1), startingPeriod);
    }

    // NOTE: proposalIndex !== proposalId
    function submitVote(uint256 proposalIndex, uint8 uintVote) public nonReentrant onlyDelegate {
        address memberAddress = memberAddressByDelegateKey[msg.sender];
        Member storage member = members[memberAddress];

        require(proposalIndex < proposalQueue.length, "proposal !exist");
        Proposal storage proposal = proposals[proposalQueue[proposalIndex]];

        require(uintVote < 3, "!vote");
        Vote vote = Vote(uintVote);

        require(getCurrentPeriod() >= proposal.startingPeriod, "voting < start");
        require(!hasVotingPeriodExpired(proposal.startingPeriod), "voting > expire");
        require(proposal.votesByMember[memberAddress] == Vote.Null, "member voted");
        require(vote == Vote.Yes || vote == Vote.No, "!vote");

        proposal.votesByMember[memberAddress] = vote;

        if (vote == Vote.Yes) {
            proposal.yesVotes = proposal.yesVotes.add(member.shares);

            // set highest index (latest) yes vote - must be processed for member to ragequit
            if (proposalIndex > member.highestIndexYesVote) {
                member.highestIndexYesVote = proposalIndex;
            }

            // set maximum of total shares encountered at a yes vote - used to bound dilution for yes voters
            if (totalShares.add(totalFunds) > proposal.maxTotalSharesAndFundsAtYesVote) {
                proposal.maxTotalSharesAndFundsAtYesVote = totalShares.add(totalFunds);
            }

        } else if (vote == Vote.No) {
            proposal.noVotes = proposal.noVotes.add(member.shares);
        }
     
        // NOTE: subgraph indexes by proposalId not proposalIndex since proposalIndex isn't set untill it's been sponsored but proposal is created on submission
        emit SubmitVote(proposalQueue[proposalIndex], proposalIndex, msg.sender, memberAddress, uintVote);
    }

    function _processPassedProposal(Proposal storage proposal) internal {
        proposal.flags[2] = true; // didPass

        // if the applicant is already a member, add to their existing shares & funds
        if (members[proposal.proposalAddresses[0]].exists) {
            members[proposal.proposalAddresses[0]].shares = members[proposal.proposalAddresses[0]].shares.add(proposal.sharesRequested);
            members[proposal.proposalAddresses[0]].funds = members[proposal.proposalAddresses[0]].funds.add(proposal.fundsRequested);

        // the applicant is a new member, create a new record for them
        } else {
            // if the applicant address is already taken by a member's delegateKey, reset it to their member address
            if (members[memberAddressByDelegateKey[proposal.proposalAddresses[0]]].exists) {
                address memberToOverride = memberAddressByDelegateKey[proposal.proposalAddresses[0]];
                memberAddressByDelegateKey[memberToOverride] = memberToOverride;
                members[memberToOverride].delegateKey = memberToOverride;
            }

            // use applicant address as delegateKey by default
            members[proposal.proposalAddresses[0]] = Member(proposal.proposalAddresses[0], proposal.sharesRequested, proposal.fundsRequested, true, 0, 0);
            memberAddressByDelegateKey[proposal.proposalAddresses[0]] = proposal.proposalAddresses[0];
        }

        // mint new shares & funds
        totalShares = totalShares.add(proposal.sharesRequested);
        totalFunds = totalFunds.add(proposal.fundsRequested);

        // if the proposal stake is the first tokens of its kind to make it into the bank, increment total bank tokens
        if (userTokenBalances[BANK][proposal.stakeToken] == 0 && proposal.stakeOffered > 0) {
            totalBankTokens += 1;
        }

        unsafeInternalTransfer(ESCROW, BANK, proposal.stakeToken, proposal.stakeOffered);
        unsafeInternalTransfer(BANK, proposal.proposalAddresses[0], proposal.paymentToken, proposal.paymentRequested);

        // if the proposal spends 100% of bank balance for a token, decrement total bank tokens
        if (userTokenBalances[BANK][proposal.paymentToken] == 0 && proposal.paymentRequested > 0) {
            totalBankTokens -= 1;
        }
    }

    function processProposal(uint256 proposalIndex) public nonReentrant {
        _validateProposalForProcessing(proposalIndex);

        uint256 proposalId = proposalQueue[proposalIndex];
        Proposal storage proposal = proposals[proposalId];

        require(!proposal.flags[4] && !proposal.flags[5], "!standard proposal");

        proposal.flags[1] = true; // processed

        bool didPass = _didPass(proposalIndex);

        // Make the proposal fail if it is requesting more tokens as payment than the available bank balance
        if (proposal.paymentRequested > userTokenBalances[BANK][proposal.paymentToken]) {
            didPass = false;
        }

        // PROPOSAL PASSED
        if (didPass) {
            _processPassedProposal(proposal);
        // PROPOSAL FAILED
        } else {
            // return all tokens to the proposer (not the applicant, because funds come from proposer)
            unsafeInternalTransfer(ESCROW, proposal.proposalAddresses[1], proposal.stakeToken, proposal.stakeOffered);
        }

        _returnDeposit(proposal.proposalAddresses[2]);

        emit ProcessProposal(proposalIndex, proposalId, didPass);
    }

    function processWhitelistProposal(uint256 proposalIndex) public nonReentrant {
        _validateProposalForProcessing(proposalIndex);

        uint256 proposalId = proposalQueue[proposalIndex];
        Proposal storage proposal = proposals[proposalId];

        require(proposal.flags[4], "!whitelist");

        proposal.flags[1] = true; // processed

        bool didPass = _didPass(proposalIndex);

        if (didPass) {
            proposal.flags[2] = true; // didPass

            tokenWhitelist[address(proposal.stakeToken)] = true;
            approvedTokens.push(proposal.stakeToken);
        }

        proposedToWhitelist[address(proposal.stakeToken)] = false;

        _returnDeposit(proposal.proposalAddresses[2]);

        emit ProcessWhitelistProposal(proposalIndex, proposalId, didPass);
    }

    function processKickProposal(uint256 proposalIndex) public nonReentrant {
        _validateProposalForProcessing(proposalIndex);

        uint256 proposalId = proposalQueue[proposalIndex];
        Proposal storage proposal = proposals[proposalId];

        require(proposal.flags[5], "!kick");

        proposal.flags[1] = true; // processed

        bool didPass = _didPass(proposalIndex);

        if (didPass) {
            proposal.flags[2] = true; // didPass
            Member storage member = members[proposal.proposalAddresses[0]];
            member.banned = proposalIndex;

            // transfer shares to funds
            member.funds = member.funds.add(member.shares);
            totalShares = totalShares.sub(member.shares);
            totalFunds = totalFunds.add(member.shares);
            member.shares = 0; // revoke all shares
        }

        proposedToKick[proposal.proposalAddresses[0]] = false;

        _returnDeposit(proposal.proposalAddresses[2]);

        emit ProcessVAOKickProposal(proposalIndex, proposalId, didPass);
    }

    function _didPass(uint256 proposalIndex) internal view returns  (bool didPass) {
        Proposal storage proposal = proposals[proposalQueue[proposalIndex]];

        didPass = proposal.yesVotes > proposal.noVotes;

        // Make the proposal fail if the dilutionBound is exceeded
        if ((totalShares.add(totalFunds)).mul(dilutionBound) < proposal.maxTotalSharesAndFundsAtYesVote) {
            didPass = false;
        }

        // Make the proposal fail if the applicant is banned
        // - for standard proposals, we don't want the applicant to get any shares/funds/payment
        // - for kick proposals, we should never be able to propose to kick a banned member (or have two kick proposals active), so it doesn't matter
        if (members[proposal.proposalAddresses[0]].banned != 0) {
            didPass = false;
        }

        return didPass;
    }

    function _validateProposalForProcessing(uint256 proposalIndex) internal view {
        require(proposalIndex < proposalQueue.length, "!proposal");
        Proposal storage proposal = proposals[proposalQueue[proposalIndex]];

        require(getCurrentPeriod() >= proposal.startingPeriod.add(votingPeriodLength).add(gracePeriodLength), "proposal is not ready to be processed");
        require(proposal.flags[1] == false, "proposal processed");
        require(proposalIndex == 0 || proposals[proposalQueue[proposalIndex.sub(1)]].flags[1], "previous proposal !processed");
    }

    function _returnDeposit(address sponsor) internal {
        unsafeInternalTransfer(ESCROW, msg.sender, depositToken, processingReward);
        unsafeInternalTransfer(ESCROW, sponsor, depositToken, proposalDeposit.sub(processingReward));
    }

    function ragequit(uint256 sharesToBurn, uint256 fundsToBurn) public nonReentrant onlyMember {
        _ragequit(msg.sender, sharesToBurn, fundsToBurn);
    }

    function _ragequit(address memberAddress, uint256 sharesToBurn, uint256 fundsToBurn) internal {
        uint256 initialTotalSharesAndFunds = totalShares.add(totalFunds);

        Member storage member = members[memberAddress];

        require(member.shares >= sharesToBurn, "!shares");
        require(member.funds >= fundsToBurn, "!funds");

        require(canRagequit(member.highestIndexYesVote), "!max(proposal process)");

        uint256 sharesAndFundsToBurn = sharesToBurn.add(fundsToBurn);

        // burn shares and funds
        member.shares = member.shares.sub(sharesToBurn);
        member.funds = member.funds.sub(fundsToBurn);
        totalShares = totalShares.sub(sharesToBurn);
        totalFunds = totalFunds.sub(fundsToBurn);

        for (uint256 i = 0; i < approvedTokens.length; i++) {
            uint256 amountToRagequit = fairShare(userTokenBalances[BANK][approvedTokens[i]], sharesAndFundsToBurn, initialTotalSharesAndFunds);
            if (amountToRagequit > 0) { // gas optimization to allow a higher maximum token limit
                // deliberately not using safemath here to keep overflows from preventing the function execution (which would break ragekicks)
                // if a token overflows, it is because the supply was artificially inflated to oblivion, so we probably don't care about it anyways
                userTokenBalances[BANK][approvedTokens[i]] -= amountToRagequit;
                userTokenBalances[memberAddress][approvedTokens[i]] += amountToRagequit;
            }
        }

        emit Ragequit(msg.sender, sharesToBurn, fundsToBurn);
    }

    function ragekick(address memberToKick) public nonReentrant {
        Member storage member = members[memberToKick];

        require(member.banned != 0, "member !banned");
        require(member.funds > 0, "!member"); // note - should be impossible for banned member to have shares
        require(canRagequit(member.highestIndexYesVote), "!max(proposal process)");

        _ragequit(memberToKick, 0, member.funds);
    }

    function withdrawBalance(address token, uint256 amount) public nonReentrant {
        _withdrawBalance(token, amount);
    }

    function withdrawBalances(address[] memory tokens, uint256[] memory amounts, bool maxWithdraw) public nonReentrant {
        require(tokens.length == amounts.length, "!length");

        for (uint256 i=0; i < tokens.length; i++) {
            uint256 withdrawAmount = amounts[i];
            if (maxWithdraw) { // withdraw the maximum balance
                withdrawAmount = userTokenBalances[msg.sender][tokens[i]];
            }

            _withdrawBalance(tokens[i], withdrawAmount);
        }
    }
    
    function _withdrawBalance(address token, uint256 amount) internal {
        require(userTokenBalances[msg.sender][token] >= amount, "!balance");
        unsafeSubtractFromBalance(msg.sender, token, amount);
        require(IERC20(token).transfer(msg.sender, amount), "transfer failed");
        emit Withdraw(msg.sender, token, amount);
    }

    function collectTokens(address token) public onlyDelegate nonReentrant {
        uint256 amountToCollect = IERC20(token).balanceOf(address(this)).sub(userTokenBalances[TOTAL][token]);
        // only collect if 1) there are tokens to collect 2) token is whitelisted 3) token has non-zero balance
        require(amountToCollect > 0, "!tokens");
        require(tokenWhitelist[token], "token !whitelisted");
        require(userTokenBalances[BANK][token] > 0, "token bal = 0");
        
        unsafeAddToBalance(BANK, token, amountToCollect);
        emit TokensCollected(token, amountToCollect);
    }

    // NOTE: requires that delegate key which sent the original proposal cancels, msg.sender == proposal.proposer
    function cancelProposal(uint256 proposalId) public nonReentrant {
        Proposal storage proposal = proposals[proposalId];
        require(!proposal.flags[0], "proposal sponsored");
        require(!proposal.flags[3], "proposal cancelled");
        require(msg.sender == proposal.proposalAddresses[1], "!proposer");

        proposal.flags[3] = true; // cancelled
        
        unsafeInternalTransfer(ESCROW, proposal.proposalAddresses[1], proposal.stakeToken, proposal.stakeOffered);
        emit CancelProposal(proposalId, msg.sender);
    }

    function updateDelegateKey(address newDelegateKey) public nonReentrant onlyShareholder {
        require(newDelegateKey != address(0), "!newDelegateKey");

        // skip checks if member is setting the delegate key to their member address
        if (newDelegateKey != msg.sender) {
            require(!members[newDelegateKey].exists, "cannot overwrite existing members");
            require(!members[memberAddressByDelegateKey[newDelegateKey]].exists, "cannot overwrite existing delegate keys");
        }

        Member storage member = members[msg.sender];
        memberAddressByDelegateKey[member.delegateKey] = address(0);
        memberAddressByDelegateKey[newDelegateKey] = msg.sender;
        member.delegateKey = newDelegateKey;

        emit UpdateDelegateKey(msg.sender, newDelegateKey);
    }

    // can only ragequit if the latest proposal you voted YES on has been processed
    function canRagequit(uint256 highestIndexYesVote) public view returns (bool) {
        require(highestIndexYesVote < proposalQueue.length, "!proposal");
        return proposals[proposalQueue[highestIndexYesVote]].flags[1];
    }

    function hasVotingPeriodExpired(uint256 startingPeriod) public view returns (bool) {
        return getCurrentPeriod() >= startingPeriod.add(votingPeriodLength);
    }

    /***************
    GETTER FUNCTIONS
    ***************/

    function max(uint256 x, uint256 y) internal pure returns (uint256) {
        return x >= y ? x : y;
    }

    function getCurrentPeriod() public view returns (uint256) {
        return block.timestamp.sub(creationTime).div(periodDuration);
    }

    function getProposalQueueLength() public view returns (uint256) {
        return proposalQueue.length;
    }

    function getProposalAddresses(uint256 proposalId) public view returns (address[3] memory) {
        return proposals[proposalId].proposalAddresses;
    }

    function getProposalFlags(uint256 proposalId) public view returns (bool[6] memory) {
        return proposals[proposalId].flags;
    }

    function getUserTokenBalance(address user, address token) public view returns (uint256) {
        return userTokenBalances[user][token];
    }

    function getMemberProposalVote(address memberAddress, uint256 proposalIndex) public view returns (Vote) {
        require(members[memberAddress].exists, "!member");
        require(proposalIndex < proposalQueue.length, "!proposal");
        return proposals[proposalQueue[proposalIndex]].votesByMember[memberAddress];
    }

    function getTokenCount() public view returns (uint256) {
        return approvedTokens.length;
    }

    /***************
    HELPER FUNCTIONS
    ***************/
    function unsafeAddToBalance(address user, address token, uint256 amount) internal {
        userTokenBalances[user][token] += amount;
        userTokenBalances[TOTAL][token] += amount;
    }

    function unsafeSubtractFromBalance(address user, address token, uint256 amount) internal {
        userTokenBalances[user][token] -= amount;
        userTokenBalances[TOTAL][token] -= amount;
    }

    function unsafeInternalTransfer(address from, address to, address token, uint256 amount) internal {
        unsafeSubtractFromBalance(from, token, amount);
        unsafeAddToBalance(to, token, amount);
    }

    function fairShare(uint256 balance, uint256 shares, uint256 totalFairShares) internal pure returns (uint256) {
        require(totalFairShares != 0, "!shares");

        if (balance == 0) { return 0; }

        uint256 prod = balance * shares;

        if (prod / balance == shares) { // no overflow in multiplication above?
            return prod / totalFairShares;
        }

        return (balance / totalFairShares) * shares;
    }
}
