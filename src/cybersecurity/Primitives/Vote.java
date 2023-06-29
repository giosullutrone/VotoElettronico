package cybersecurity.Primitives;

import java.io.Serializable;

public class Vote implements Serializable{
    private final VoteCredential voteCredential;
    private final byte[] vote;

    public Vote(VoteCredential voteCredential, byte[] vote) {
        this.voteCredential = voteCredential;
        this.vote = vote;
    }

    public VoteCredential getVoteCredential() {
        return voteCredential;
    }

    public byte[] getVote() {
        return vote;
    }    
}
