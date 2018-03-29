<template>
  <b-row>
    <b-col cols="12">
      <h2>
        User Dashboard
        <b-link href="/">(Index)</b-link>
      </h2>
      <b-jumbotron>
        <template slot="header">
          {{user.first_name}}
        </template>
        <template slot="lead">
          First Name: {{user.first_name}}<br>
          Last Name: {{user.last_name}}<br>
          Email: {{user.email}}<br>
          
          Schedule: {{user.schedule}}<br>
          Payment info stuff<br>
          Find Providers and their plans<br>
          Settings -> Move Edit and Delete here<br>
        </template>

        <b-table dark striped hover :items="plans" :fields="fields">
          <template slot="actions" scope="row">
            
            <b-btn size="sm" @click.stop="details(row.item._id)"></b-btn>
            
          </template>
        </b-table>

        <hr class="my-4">
        <p>
          Updated Date: {{user.updated_date}}
        </p>
        <b-btn variant="success" @click.stop="edituser(user._id)">Edit</b-btn>
        <b-btn variant="danger" @click.stop="deleteuser(user._id)">Delete</b-btn>
      </b-jumbotron>
    </b-col>
  </b-row>
</template>

<script>

import axios from 'axios'

export default {
  name: 'ShowUser',
  data () {
    return {
      fields: {
        title: { label: 'Title', sortable: true, 'class': 'text-center' },
        date: { label: 'Date', sortable: true, 'class': 'text-center' },
        time: { label: 'Time', 'class': 'text-center' },
        provider: { label: 'Provider', 'class' : 'text-center'}
      },
      user: [],
      errors: []
    }
  },
  created () {
    axios.get(`http://localhost:3000/plan`)
    .then(response => {
      this.plans = response.data
    })
    .catch(e => {
      this.errors.push(e)
    }),
    axios.get(`http://localhost:3000/user/` + this.$route.params.id)
    .then(response => {
      this.user = response.data
    })
    .catch(e => {
      this.errors.push(e)
    })
  },
  methods: {
    edituser (userid) {
      this.$router.push({
        name: 'EditUser',
        params: { id: userid }
      })
    },
    deleteuser (userid) {
      axios.delete('http://localhost:3000/user/' + userid)
      .then((result) => {
        this.$router.push({
          name: 'ListUser'
        })
      })
      .catch(e => {
        this.errors.push(e)
      })
    }
  }
}
</script>

<style>
  .jumbotron {
    padding: 2rem;
  }
</style>