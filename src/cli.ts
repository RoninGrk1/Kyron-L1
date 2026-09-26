import { BASE_UNIT } from "./constants.ts";
import { allocateFromTreasury } from "./ledger/alloc.ts";
import { ChainNode } from "./node/chain.ts";
import { rpcBalance, rpcStatus, rpcSupply } from "./node/rpc.ts";
import { Wallet } from "./wallet/wallet.ts";
import { formatKrn } from "./tokenomics/supply.ts";

const cmd = process.argv[2] ?? "demo";

if (cmd === "supply") {
  console.log(JSON.stringify(rpcSupply(), null, 2));
  process.exit(0);
}

if (cmd === "demo" || cmd === "node") {
  const node = new ChainNode();
  const alice = new Wallet();
  const bob = new Wallet();
  allocateFromTreasury(node.state, alice.address, 1_000_000n * BASE_UNIT);
  allocateFromTreasury(node.state, bob.address, 50_000n * BASE_UNIT);

  node.submit(alice.setViewing(node.state));
  node.produceBlock(1);

  node.submit(alice.transfer(node.state, bob.address, 1_000n * BASE_UNIT));
  node.produceBlock(2);

  node.submit(alice.stake(node.state, 20_000n * BASE_UNIT));
  node.produceBlock(3);

  node.submit(alice.shield(node.state, 500n * BASE_UNIT, "seed note"));
  node.produceBlock(4);

  node.submit(alice.shieldedTransfer(node.state, bob.keys.view.publicKey, bob.address, 100n * BASE_UNIT, "private pay"));
  node.produceBlock(5);

  bob.scan(node.state);

  console.log(JSON.stringify({
    status: rpcStatus(node),
    alice: {
      address: alice.address,
      public: rpcBalance(node, alice.address),
      shielded: formatKrn(alice.shieldedBalance()),
    },
    bob: {
      address: bob.address,
      public: rpcBalance(node, bob.address),
      shielded: formatKrn(bob.shieldedBalance()),
    },
  }, null, 2));
}
