module ct_wrapper_fsm(
    input logic hs_in_posedge, 
    input logic hs_in_negedge,
    input logic hs_out_ct_cpy_posedge,
    input logic hs_out_orig_posedge,
    input logic hs_out_ct_cpy_negedge,
    input logic hs_out_orig_negedge,
    input logic rst_ni,
    input logic clk_i,
    output logic gate_en, 
    output logic rst_n_en
    );

    typedef enum logic [1:0] {
        IDLE, BUSY, GATE
    } fsm_state_e;

    fsm_state_e state_d, state_q;
    assign gate_en = state_q[1];
    always_comb begin
        state_d = state_q;
        rst_n_en = 1'b1;
        unique case (state_q)
            IDLE: begin
                if(hs_in_posedge)  // maybe this should be at first state change? e.g. record initial state
                    state_d = BUSY; // posedge on input handshake. goto BUSY
            end
            BUSY: begin // 
                if(hs_in_negedge) begin  // when next state is the initial state in both original and ct copy
                    state_d = IDLE;
                    rst_n_en = 1'b0; // we should do a synchronous reset s.t. we enter IDLE in a reset' state without changing outputs in the reset cycle
                end else if(hs_out_orig_posedge & ~hs_out_ct_cpy_posedge) // when next state between original and ct_cpy differ
                    state_d = GATE;
        
            end
            GATE: begin
                if(hs_in_negedge) begin // when next state of ct copy is the initial state
                    state_d = IDLE;
                    rst_n_en = 1'b0; // when we go from BUF to IDLE, reset the module
                end else if(hs_out_ct_cpy_posedge) begin // when next state of ct_cpy state is not current state and not initial state
                    state_d = BUSY;
                    rst_n_en = 1'b0;
                end
            end
        endcase
    end

    always @(posedge clk_i, negedge rst_ni) begin
        if(!rst_ni)
            state_q <= IDLE;
        else
            state_q <= state_d;
    end
endmodule