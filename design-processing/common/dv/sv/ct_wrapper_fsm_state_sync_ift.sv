module ct_wrapper_fsm #
    (
    parameter N_STATE_BITS = 10 // this can be larger than the actual number of state bits in the FSMs. Yosys fills them with 0 in this case.
    )
    (
    input logic [N_STATE_BITS-1:0] state_d_orig,
    input logic [N_STATE_BITS-1:0] state_q_orig,
    input logic [N_STATE_BITS-1:0] state_d_ct_cpy,
    input logic [N_STATE_BITS-1:0] state_d_orig,
    input logic [N_STATE_BITS-1:0] state_q_orig_t0,
    input logic [N_STATE_BITS-1:0] state_d_ct_cpy_t0,
    input logic [N_STATE_BITS-1:0] state_q_ct_cpy_t0,
    input logic [N_STATE_BITS-1:0] state_q_ct_cpy_t0,
    input logic rst_ni,
    input logic clk_i,
    output logic gate_en, 
    output logic rst_en
    input logic rst_ni_t0,
    input logic clk_i_t0,
    output logic gate_en_t0,
    output logic rst_e_t0
    );

    assign rst_e_t0 = 1'b0;
    assign gate_en_t0 = 1'b0;

    typedef enum logic [1:0] {
        IDLE, BUSY, GATE
    } fsm_state_e;

    fsm_state_e state_d, state_q;
  //  logic [N_STATE_BITS-1:0] final_state_d, final_state_q;
    always_comb begin
        state_d = state_q;
 //       final_state_d = final_state_q;
        rst_en = 1'b0;
        gate_en = 1'b0;
        
        unique case (state_q)
            IDLE: begin
                if(state_q_orig == N_STATE_BITS'b0 && state_d_orig != state_q_orig)  // maybe this should be at first state change? e.g. record initial state
                    state_d = BUSY; // posedge on input handshake. goto BUSY
                //assert(state_q_ct_cpy == state_q_orig);
            end
            BUSY: begin // 
                if(state_d_orig == N_STATE_BITS'b0 && state_d_ct_cpy == N_STATE_BITS'b0) begin  // when next state is the initial state in both original and ct copy
                    state_d = IDLE;
                    rst_en = 1'b1; // we should do a synchronous reset s.t. we enter IDLE in a reset' state without changing outputs in the reset cycle
                end else if(state_d_orig == N_STATE_BITS'b0 && state_d_ct_cpy != state_d_orig) begin // when next state in the original but not the ct copy is the initial state
                    state_d = GATE;
   //                 final_state_d = state_q_orig; // record the final state of the original to match with in the ct copy when finishing gating
                end 
            end
            GATE: begin
                gate_en = 1'b1;
                if(state_d_ct_cpy == N_STATE_BITS'b0) begin // when next state of ct copy is the initial state or the current state is the final state recorded earlier
                    state_d = IDLE;
                    rst_en = 1'b1; // we should do a synchronous reset s.t. we enter IDLE in a reset' state without changing outputs in the reset cycle
                end else if(state_d_ct_cpy == state_d_orig) begin // when next state of ct_cpy is not the initial state and matches the next state of the original instance 
                    state_d = BUSY;
                    rst_en = 1'b1; // we should do a synchronous reset s.t. we enter IDLE in a reset' state without changing outputs in the reset cycle
                end 
                    //assert(state_d_ct_cpy != state_d_orig);
            end
        endcase
    end

    always @(posedge clk_i, negedge rst_ni) begin
        if(!rst_ni)
            state_q <= IDLE;
        else
            state_q <= state_d;
    end


//    always @(posedge clk_i, negedge rst_ni) begin
//        if(!rst_ni)
//            final_state_q <= N_STATE_BITS'b0;
//        else
//            final_state_q <= final_state_d;
//    end
endmodule